//
//  PeerTransport.swift
//  Pigeon
//
//  Dual-role CoreBluetooth driver: every device is simultaneously a BLE
//  central (scans, connects, writes) and a peripheral (advertises, receives),
//  so any two Pigeon devices in range can exchange data over one connection.
//
//  This layer is deliberately "dumb pipe": it moves opaque byte messages and
//  knows nothing about encryption. Messages are fragmented to fit BLE MTUs via
//  the `pigeon-mesh` fragmenter and reassembled per source. Encryption (the Olm
//  session) and mesh relaying layer on top of this.
//
//  Fragment size follows the negotiated ATT MTU per connection, with a
//  conservative floor so any link stays safe. We deliberately keep
//  write-with-response: it gives flow control and reliable long writes, and this
//  app values delivery certainty over raw throughput — MTU-sized fragments already
//  cut the number of writes. Current limitation (tracked): if two devices connect
//  to each other in both roles, a message may be delivered twice — the mesh dedup
//  layer absorbs duplicates.
//

import CoreBluetooth
import Foundation
import PigeonFFI

/// The BLE implementation of `Transport`. Drives Bluetooth discovery and
/// messaging and publishes observable state for the UI. Runs on the main actor;
/// CoreBluetooth callbacks are delivered on the main queue.
@MainActor
@Observable
final class PeerTransport: NSObject, Transport {

  let kind: TransportKind? = .bluetooth
  var status: TransportStatus = .idle
  /// Number of peers we are currently connected to (as central).
  private(set) var connectedPeerCount = 0
  /// Recent activity, newest last, surfaced by the app's diagnostics UI.
  private(set) var log: [String] = []
  private(set) var isEnabled: Bool

  /// Invoked with each fully reassembled inbound message and its source id.
  var onMessage: ((_ message: Data, _ peerID: String) -> TransportMessageDisposition)?
  /// Fired when a peer link becomes usable for sending (a write channel is
  /// discovered, or a central subscribes), so the session layer flushes pending
  /// work on the event rather than on a timer.
  var onConnectivity: (() -> Void)?

  @ObservationIgnored private var centralRef: CBCentralManager?
  @ObservationIgnored private var peripheralManagerRef: CBPeripheralManager?

  var central: CBCentralManager {
    guard let centralRef else {
      preconditionFailure("CBCentralManager used before initialization")
    }
    return centralRef
  }

  var peripheralManager: CBPeripheralManager {
    guard let peripheralManagerRef else {
      preconditionFailure("CBPeripheralManager used before initialization")
    }
    return peripheralManagerRef
  }

  // Peripheral (server) side.
  var outboundCharacteristic: CBMutableCharacteristic?
  var subscribedCentrals: [CBCentral] = []

  // Central (client) side: retained connections and their inbound characteristic.
  var peripherals: [UUID: CBPeripheral] = [:]
  var inboundCharacteristics: [UUID: CBCharacteristic] = [:]

  // Outbound fragmenter + per-source reassemblers.
  private var fragmenter = Fragmenter()
  var reassembly = ReassemblyPool()
  private var sweepTimer: Timer?
  /// Notifications waiting for the peripheral transmit queue to drain.
  private var pendingNotifications: [Data] = []
  /// Whether our GATT service has been added (or restored), so we don't re-add it.
  var didAddService = false

  override convenience init() {
    self.init(enabled: true)
  }

  init(enabled: Bool) {
    isEnabled = enabled
    super.init()
    // Restoration identifiers let iOS relaunch us in the background on a BLE
    // event after the app was terminated (see willRestoreState handlers).
    centralRef = CBCentralManager(
      delegate: self,
      queue: nil,
      options: [CBCentralManagerOptionRestoreIdentifierKey: "com.isaiah-harville.Pigeon.central"])
    peripheralManagerRef = CBPeripheralManager(
      delegate: self,
      queue: nil,
      options: [
        CBPeripheralManagerOptionRestoreIdentifierKey: "com.isaiah-harville.Pigeon.peripheral"
      ])
    // Periodically recover stuck links: keep scanning and reconnect any
    // known peer that isn't currently connected.
    if enabled { startSweepTimer() }
  }

  private func startSweepTimer() {
    guard sweepTimer == nil else { return }
    sweepTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
      guard let self else { return }
      Task { @MainActor in self.sweep() }
    }
  }

  private func sweep() {
    guard isEnabled else { return }
    guard central.state == .poweredOn else { return }
    startScanningIfReady()
    for peripheral in peripherals.values
    where peripheral.state != .connected && peripheral.state != .connecting {
      central.connect(peripheral, options: nil)
    }
  }

  /// Broadcasts `message` to every connected peer, in both roles. BLE is a flood
  /// transport, so the `recipient` hint is ignored — the mesh addresses and
  /// deduplicates above this layer.
  func broadcast(_ message: Data) {
    broadcast(message, to: nil)
  }

  func broadcast(_ message: Data, to _: Data?) {
    guard isEnabled else { return }
    let fragments: [Fragment]
    do {
      fragments = try fragmenter.fragment(
        message, maxPayloadPerFragment: fragmentPayloadBudget())
    } catch {
      note(.fragmentationFailed)
      return
    }

    var writeTargets = 0
    var notified = false
    for fragment in fragments {
      let bytes = fragment.encoded()

      // Central path: write to each connected peripheral's inbound characteristic.
      for (id, peripheral) in peripherals where peripheral.state == .connected {
        if let characteristic = inboundCharacteristics[id] {
          peripheral.writeValue(bytes, for: characteristic, type: .withResponse)
          writeTargets += 1
        }
      }

      // Peripheral path: notify subscribed centrals via outbound characteristic.
      // updateValue can fail when the transmit queue is full; queue it and
      // resend from peripheralManagerIsReady so fragments are never dropped.
      if outboundCharacteristic != nil, !subscribedCentrals.isEmpty {
        enqueueNotification(bytes)
        notified = true
      }
    }
    let paths = writeTargets > 0 || notified
    note(paths ? .transportBroadcast : .transportNoPath)
  }

  func refreshConnections() {
    guard isEnabled else { return }
    guard central.state == .poweredOn else { return }
    central.stopScan()
    startScanningIfReady()
    sweep()
    for peripheral in peripherals.values where peripheral.state == .connected {
      peripheral.discoverServices([BluetoothConstants.service])
    }
    note(.transportRefresh)
  }

  func setEnabled(_ enabled: Bool) {
    guard isEnabled != enabled else { return }
    isEnabled = enabled
    if enabled {
      startSweepTimer()
      installPeripheralServiceIfReady()
      startScanningIfReady()
      sweep()
    } else {
      sweepTimer?.invalidate()
      sweepTimer = nil
      central.stopScan()
      for peripheral in peripherals.values {
        central.cancelPeripheralConnection(peripheral)
      }
      peripheralManager.stopAdvertising()
      peripheralManager.removeAllServices()
      didAddService = false
      outboundCharacteristic = nil
      subscribedCentrals.removeAll()
      inboundCharacteristics.removeAll()
      pendingNotifications.removeAll()
      connectedPeerCount = 0
      status = .idle
    }
  }

  // MARK: - Fragment sizing

  /// The per-fragment payload budget for this broadcast: the smallest usable
  /// length negotiated across every path this message will travel (each connected
  /// peripheral's write length and each subscribed central's notify length), so a
  /// link that negotiated a larger ATT MTU sends fewer fragments while every target
  /// can still receive each one. Falls back to the conservative floor when no path
  /// is up yet. A single fragmentation per broadcast keeps the dumb-pipe model.
  private func fragmentPayloadBudget() -> Int {
    var lengths: [Int] = []
    for (id, peripheral) in peripherals
    where peripheral.state == .connected && inboundCharacteristics[id] != nil {
      lengths.append(peripheral.maximumWriteValueLength(for: .withResponse))
    }
    for central in subscribedCentrals {
      lengths.append(central.maximumUpdateValueLength)
    }
    return Self.fragmentPayloadBudget(smallestNegotiatedLength: lengths.min())
  }

  /// Clamps the smallest negotiated value length (whole-fragment bytes, header
  /// included) to a usable payload size: subtract the fragment header, never go
  /// below the safe floor nor above the ceiling. `nil` (no live path) yields the
  /// floor. Pure, so the MTU policy is unit-tested without CoreBluetooth.
  static func fragmentPayloadBudget(smallestNegotiatedLength: Int?) -> Int {
    guard let length = smallestNegotiatedLength else {
      return BluetoothConstants.maxFragmentPayload
    }
    let usable = length - BluetoothConstants.fragmentHeaderSize
    return min(
      max(usable, BluetoothConstants.maxFragmentPayload),
      BluetoothConstants.maxFragmentPayloadCeiling)
  }

  // MARK: - Helpers

  func note(_ event: DiagnosticEvent) {
    DiagnosticLog.record(event, in: &log, limit: 200)
  }

  func updateConnectedCount() {
    connectedPeerCount = peripherals.values.filter { $0.state == .connected }.count
  }

  /// Queues a notification and tries to flush. Notifications that don't fit the
  /// current transmit queue are retried in `peripheralManagerIsReady`.
  private func enqueueNotification(_ bytes: Data) {
    pendingNotifications.append(bytes)
    flushNotifications()
  }

  func flushNotifications() {
    guard let characteristic = outboundCharacteristic else { return }
    while let next = pendingNotifications.first {
      if peripheralManager.updateValue(next, for: characteristic, onSubscribedCentrals: nil) {
        pendingNotifications.removeFirst()
      } else {
        break  // queue full; resume when peripheralManagerIsReady fires
      }
    }
  }

  /// Decodes a fragment from raw BLE bytes and delivers a completed message.
  func receive(_ data: Data, from source: UUID) {
    guard isEnabled else { return }
    do {
      let fragment = try Fragment(decoding: data)
      if let message = try reassembly.ingest(fragment, from: source) {
        note(.transportReceived)
        _ = onMessage?(message, source.uuidString)
      }
    } catch {
      note(.malformedFragment)
    }
  }

  func startScanningIfReady() {
    guard isEnabled else { return }
    guard central.state == .poweredOn else { return }
    central.scanForPeripherals(
      withServices: [BluetoothConstants.service],
      options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    status = .scanning
    note(.transportScanning)
  }
}
