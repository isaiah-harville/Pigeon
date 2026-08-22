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

// The central and peripheral delegates intentionally live beside the state they
// mutate so the radio lifecycle remains auditable as one unit.
// swiftlint:disable file_length

/// The BLE implementation of `Transport`. Drives Bluetooth discovery and
/// messaging and publishes observable state for the UI. Runs on the main actor;
/// CoreBluetooth callbacks are delivered on the main queue.
@MainActor
@Observable
final class PeerTransport: NSObject, Transport {

  let kind: TransportKind? = .bluetooth
  private(set) var status: TransportStatus = .idle
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

  private var central: CBCentralManager {
    guard let centralRef else {
      preconditionFailure("CBCentralManager used before initialization")
    }
    return centralRef
  }

  private var peripheralManager: CBPeripheralManager {
    guard let peripheralManagerRef else {
      preconditionFailure("CBPeripheralManager used before initialization")
    }
    return peripheralManagerRef
  }

  // Peripheral (server) side.
  private var outboundCharacteristic: CBMutableCharacteristic?
  private var subscribedCentrals: [CBCentral] = []

  // Central (client) side: retained connections and their inbound characteristic.
  private var peripherals: [UUID: CBPeripheral] = [:]
  private var inboundCharacteristics: [UUID: CBCharacteristic] = [:]

  // Outbound fragmenter + per-source reassemblers.
  private var fragmenter = Fragmenter()
  private var reassembly = ReassemblyPool()
  private var sweepTimer: Timer?
  /// Notifications waiting for the peripheral transmit queue to drain.
  private var pendingNotifications: [Data] = []
  /// Whether our GATT service has been added (or restored), so we don't re-add it.
  private var didAddService = false

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

  private func note(_ event: DiagnosticEvent) {
    DiagnosticLog.record(event, in: &log, limit: 200)
  }

  private func updateConnectedCount() {
    connectedPeerCount = peripherals.values.filter { $0.state == .connected }.count
  }

  /// Queues a notification and tries to flush. Notifications that don't fit the
  /// current transmit queue are retried in `peripheralManagerIsReady`.
  private func enqueueNotification(_ bytes: Data) {
    pendingNotifications.append(bytes)
    flushNotifications()
  }

  private func flushNotifications() {
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
  private func receive(_ data: Data, from source: UUID) {
    guard isEnabled else { return }
    do {
      let fragment = try Fragment(decoding: data)
      if let message = try reassembly.reassembler(for: source).ingest(fragment) {
        note(.transportReceived)
        _ = onMessage?(message, source.uuidString)
      }
    } catch {
      note(.malformedFragment)
    }
  }

  private func startScanningIfReady() {
    guard isEnabled else { return }
    guard central.state == .poweredOn else { return }
    central.scanForPeripherals(
      withServices: [BluetoothConstants.service],
      options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    status = .scanning
    note(.transportScanning)
  }
}

// MARK: - CBCentralManagerDelegate

extension PeerTransport: CBCentralManagerDelegate {
  func centralManagerDidUpdateState(_ manager: CBCentralManager) {
    guard isEnabled else {
      status = .idle
      return
    }
    switch manager.state {
    case .poweredOn: startScanningIfReady()
    case .unauthorized: status = .unauthorized
    case .poweredOff: status = .poweredOff
    default: status = .idle
    }
  }

  func centralManager(_ manager: CBCentralManager, willRestoreState dict: [String: Any]) {
    guard let restored = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] else {
      return
    }
    guard isEnabled else {
      for peripheral in restored { manager.cancelPeripheralConnection(peripheral) }
      return
    }
    // Reattach to peripherals iOS restored after relaunching us in the background.
    for peripheral in restored {
      peripheral.delegate = self
      peripherals[peripheral.identifier] = peripheral
      if peripheral.state == .connected {
        peripheral.discoverServices([BluetoothConstants.service])  // refresh characteristics
      } else {
        manager.connect(peripheral, options: nil)
      }
    }
    updateConnectedCount()
    note(.transportRestored)
  }

  func centralManager(
    _ manager: CBCentralManager, didDiscover peripheral: CBPeripheral,
    advertisementData _: [String: Any], rssi _: NSNumber
  ) {
    guard isEnabled else { return }
    if let existing = peripherals[peripheral.identifier] {
      // Known peer that dropped (e.g. its app restarted): reconnect.
      if existing.state != .connected { manager.connect(existing, options: nil) }
      return
    }
    peripherals[peripheral.identifier] = peripheral  // retain before connecting
    note(.peerDiscovered)
    manager.connect(peripheral, options: nil)
  }

  func centralManager(_ manager: CBCentralManager, didConnect peripheral: CBPeripheral) {
    guard isEnabled else {
      manager.cancelPeripheralConnection(peripheral)
      return
    }
    peripheral.delegate = self
    peripheral.discoverServices([BluetoothConstants.service])
    updateConnectedCount()
    note(.peerConnected)
  }

  func centralManager(
    _ manager: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
    error _: Error?
  ) {
    inboundCharacteristics[peripheral.identifier] = nil
    reassembly.drop(peripheral.identifier)
    updateConnectedCount()
    note(.peerDisconnected)
    guard isEnabled else { return }
    // Keep the peripheral retained and issue a pending connect: CoreBluetooth
    // reconnects automatically when the peer returns (e.g. after an app restart).
    manager.connect(peripheral, options: nil)
    startScanningIfReady()
  }

  func centralManager(
    _ manager: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
    error _: Error?
  ) {
    note(.peerConnectionFailed)
    guard isEnabled else { return }
    manager.connect(peripheral, options: nil)  // stay pending until available
  }
}

// MARK: - CBPeripheralDelegate (central-side: talking to a remote peripheral)

extension PeerTransport: CBPeripheralDelegate {
  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices _: Error?) {
    guard isEnabled else { return }
    for service in peripheral.services ?? [] where service.uuid == BluetoothConstants.service {
      peripheral.discoverCharacteristics(
        [BluetoothConstants.inbound, BluetoothConstants.outbound],
        for: service)
    }
  }

  func peripheral(
    _ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
    error _: Error?
  ) {
    guard isEnabled else { return }
    for characteristic in service.characteristics ?? [] {
      switch characteristic.uuid {
      case BluetoothConstants.inbound:
        inboundCharacteristics[peripheral.identifier] = characteristic
        note(.writeChannelReady)
        onConnectivity?()  // can write to this peer now — flush pending work
      case BluetoothConstants.outbound:
        peripheral.setNotifyValue(true, for: characteristic)  // receive peer → us
        note(.peerSubscribed)
      default:
        break
      }
    }
  }

  func peripheral(
    _ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
    error _: Error?
  ) {
    guard isEnabled else { return }
    guard let data = characteristic.value else { return }
    note(.transportReceived)
    receive(data, from: peripheral.identifier)
  }
}

// MARK: - CBPeripheralManagerDelegate (peripheral-side: serving remote centrals)

extension PeerTransport: CBPeripheralManagerDelegate {
  func peripheralManagerDidUpdateState(_ manager: CBPeripheralManager) {
    guard isEnabled else {
      manager.stopAdvertising()
      manager.removeAllServices()
      return
    }
    guard manager.state == .poweredOn else { return }
    installPeripheralServiceIfReady()
  }

  private func installPeripheralServiceIfReady() {
    guard isEnabled, peripheralManager.state == .poweredOn, !didAddService else { return }

    let inbound = CBMutableCharacteristic(
      type: BluetoothConstants.inbound,
      properties: [.write],
      value: nil,
      permissions: [.writeable])
    let outbound = CBMutableCharacteristic(
      type: BluetoothConstants.outbound,
      properties: [.notify],
      value: nil,
      permissions: [.readable])
    outboundCharacteristic = outbound

    let service = CBMutableService(type: BluetoothConstants.service, primary: true)
    service.characteristics = [inbound, outbound]
    peripheralManager.add(service)
  }

  // MARK: State restoration (relaunched in the background on a BLE event)

  func peripheralManager(
    _ manager: CBPeripheralManager,
    willRestoreState dict: [String: Any]
  ) {
    guard isEnabled else {
      manager.stopAdvertising()
      manager.removeAllServices()
      return
    }
    // Recover our advertised service so we can keep notifying restored centrals.
    if let services = dict[CBPeripheralManagerRestoredStateServicesKey] as? [CBMutableService] {
      for service in services where service.uuid == BluetoothConstants.service {
        for characteristic in service.characteristics ?? []
        where characteristic.uuid == BluetoothConstants.outbound {
          outboundCharacteristic = characteristic as? CBMutableCharacteristic
        }
        didAddService = true  // already added by the restored session
      }
      note(.transportRestored)
    }
  }

  func peripheralManager(_ manager: CBPeripheralManager, didAdd _: CBService, error _: Error?) {
    didAddService = true
    guard isEnabled else {
      manager.removeAllServices()
      didAddService = false
      return
    }
    manager.startAdvertising([
      CBAdvertisementDataServiceUUIDsKey: [BluetoothConstants.service],
      CBAdvertisementDataLocalNameKey: "Pigeon",
    ])
    note(.transportAdvertising)
  }

  func peripheralManager(_ manager: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
    guard isEnabled else {
      if let first = requests.first { manager.respond(to: first, withResult: .writeNotPermitted) }
      return
    }
    for request in requests {
      if let value = request.value {
        note(.transportReceived)
        receive(value, from: request.central.identifier)
      }
    }
    if let first = requests.first {
      manager.respond(to: first, withResult: .success)
    }
  }

  func peripheralManagerIsReady(toUpdateSubscribers _: CBPeripheralManager) {
    flushNotifications()
  }

  func peripheralManager(
    _: CBPeripheralManager, central: CBCentral,
    didSubscribeTo _: CBCharacteristic
  ) {
    guard isEnabled else { return }
    if !subscribedCentrals.contains(where: { $0.identifier == central.identifier }) {
      subscribedCentrals.append(central)
    }
    note(.peerSubscribed)
    onConnectivity?()  // can notify this central now — flush pending work
  }

  func peripheralManager(
    _: CBPeripheralManager, central: CBCentral,
    didUnsubscribeFrom _: CBCharacteristic
  ) {
    subscribedCentrals.removeAll { $0.identifier == central.identifier }
    reassembly.drop(central.identifier)
  }
}
