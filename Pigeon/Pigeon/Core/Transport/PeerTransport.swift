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
//  PigeonMesh and reassembled per source. Encryption (SecureSession) and mesh
//  relaying layer on top of this.
//
//  Current limitations (tracked): uses write-with-response (reliable but slower)
//  and a conservative fixed fragment size; if two devices connect to each other
//  in both roles, a message may be delivered twice — the mesh dedup layer
//  absorbs duplicates.
//

import CoreBluetooth
import Foundation
import PigeonMesh

/// The BLE implementation of `Transport`. Drives Bluetooth discovery and
/// messaging and publishes observable state for the UI. Runs on the main actor;
/// CoreBluetooth callbacks are delivered on the main queue.
@MainActor
@Observable
final class PeerTransport: NSObject, Transport {

  private(set) var status: TransportStatus = .idle
  /// Number of peers we are currently connected to (as central).
  private(set) var connectedPeerCount = 0
  /// Recent activity, newest last, surfaced by the app's diagnostics UI.
  private(set) var log: [String] = []

  /// Invoked with each fully reassembled inbound message and its source id.
  var onMessage: ((_ message: Data, _ peerID: String) -> Void)?

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
  private var reassemblers: [UUID: Reassembler] = [:]
  private var sweepTimer: Timer?
  /// Notifications waiting for the peripheral transmit queue to drain.
  private var pendingNotifications: [Data] = []
  /// Whether our GATT service has been added (or restored), so we don't re-add it.
  private var didAddService = false

  override init() {
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
    sweepTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
      guard let self else { return }
      Task { @MainActor in self.sweep() }
    }
  }

  private func sweep() {
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
    let fragments: [Fragment]
    do {
      fragments = try fragmenter.fragment(
        message, maxPayloadPerFragment: BluetoothConstants.maxFragmentPayload)
    } catch {
      note("Failed to fragment message: \(error)")
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
    let notifyText = notified ? " + notify" : ""
    let pathText = paths ? "" : " — NO PATH"
    let summary = "Sent \(message.count)B/\(fragments.count)f via \(writeTargets) write(s)"
    note("\(summary)\(notifyText)\(pathText)")
  }

  // MARK: - Helpers

  private func note(_ message: String) {
    log.append(message)
    if log.count > 200 { log.removeFirst(log.count - 200) }
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

  private func reassembler(for source: UUID) -> Reassembler {
    if let existing = reassemblers[source] { return existing }
    let made = Reassembler()
    reassemblers[source] = made
    return made
  }

  /// Decodes a fragment from raw BLE bytes and delivers a completed message.
  private func receive(_ data: Data, from source: UUID) {
    do {
      let fragment = try Fragment(decoding: data)
      if let message = try reassembler(for: source).ingest(fragment) {
        note("Received \(message.count)B from \(source.uuidString.prefix(8))")
        onMessage?(message, source.uuidString)
      }
    } catch {
      note("Bad fragment from \(source.uuidString.prefix(8)): \(error)")
    }
  }

  private func startScanningIfReady() {
    guard central.state == .poweredOn else { return }
    central.scanForPeripherals(
      withServices: [BluetoothConstants.service],
      options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
    status = .scanning
    note("Scanning…")
  }
}

// MARK: - CBCentralManagerDelegate

extension PeerTransport: CBCentralManagerDelegate {
  func centralManagerDidUpdateState(_ manager: CBCentralManager) {
    switch manager.state {
    case .poweredOn: startScanningIfReady()
    case .unauthorized: status = .unauthorized
    case .poweredOff: status = .poweredOff
    default: status = .idle
    }
  }

  func centralManager(_ manager: CBCentralManager, willRestoreState dict: [String: Any]) {
    // Reattach to peripherals iOS restored after relaunching us in the background.
    guard let restored = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] else {
      return
    }
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
    note("Restored \(restored.count) peer(s)")
  }

  func centralManager(
    _ manager: CBCentralManager, didDiscover peripheral: CBPeripheral,
    advertisementData _: [String: Any], rssi _: NSNumber
  ) {
    if let existing = peripherals[peripheral.identifier] {
      // Known peer that dropped (e.g. its app restarted): reconnect.
      if existing.state != .connected { manager.connect(existing, options: nil) }
      return
    }
    peripherals[peripheral.identifier] = peripheral  // retain before connecting
    note("Discovered peer \(peripheral.identifier.uuidString.prefix(8))")
    manager.connect(peripheral, options: nil)
  }

  func centralManager(_: CBCentralManager, didConnect peripheral: CBPeripheral) {
    peripheral.delegate = self
    peripheral.discoverServices([BluetoothConstants.service])
    updateConnectedCount()
    note("Connected to \(peripheral.identifier.uuidString.prefix(8))")
  }

  func centralManager(
    _ manager: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
    error _: Error?
  ) {
    inboundCharacteristics[peripheral.identifier] = nil
    reassemblers[peripheral.identifier] = nil
    updateConnectedCount()
    note("Disconnected \(peripheral.identifier.uuidString.prefix(8)); will reconnect")
    // Keep the peripheral retained and issue a pending connect: CoreBluetooth
    // reconnects automatically when the peer returns (e.g. after an app restart).
    manager.connect(peripheral, options: nil)
    startScanningIfReady()
  }

  func centralManager(
    _ manager: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
    error _: Error?
  ) {
    note("Failed to connect \(peripheral.identifier.uuidString.prefix(8)); retrying")
    manager.connect(peripheral, options: nil)  // stay pending until available
  }
}

// MARK: - CBPeripheralDelegate (central-side: talking to a remote peripheral)

extension PeerTransport: CBPeripheralDelegate {
  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices _: Error?) {
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
    for characteristic in service.characteristics ?? [] {
      switch characteristic.uuid {
      case BluetoothConstants.inbound:
        inboundCharacteristics[peripheral.identifier] = characteristic
        note("Found write channel for \(peripheral.identifier.uuidString.prefix(8))")
      case BluetoothConstants.outbound:
        peripheral.setNotifyValue(true, for: characteristic)  // receive peer → us
        note("Subscribed to \(peripheral.identifier.uuidString.prefix(8))")
      default:
        break
      }
    }
  }

  func peripheral(
    _ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
    error _: Error?
  ) {
    guard let data = characteristic.value else { return }
    note("notify-recv \(data.count)B")
    receive(data, from: peripheral.identifier)
  }
}

// MARK: - CBPeripheralManagerDelegate (peripheral-side: serving remote centrals)

extension PeerTransport: CBPeripheralManagerDelegate {
  func peripheralManagerDidUpdateState(_ manager: CBPeripheralManager) {
    guard manager.state == .poweredOn, !didAddService else { return }

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
    manager.add(service)
  }

  // MARK: State restoration (relaunched in the background on a BLE event)

  func peripheralManager(
    _: CBPeripheralManager,
    willRestoreState dict: [String: Any]
  ) {
    // Recover our advertised service so we can keep notifying restored centrals.
    if let services = dict[CBPeripheralManagerRestoredStateServicesKey] as? [CBMutableService] {
      for service in services where service.uuid == BluetoothConstants.service {
        for characteristic in service.characteristics ?? []
        where characteristic.uuid == BluetoothConstants.outbound {
          outboundCharacteristic = characteristic as? CBMutableCharacteristic
        }
        didAddService = true  // already added by the restored session
      }
      note("Restored peripheral state")
    }
  }

  func peripheralManager(_ manager: CBPeripheralManager, didAdd _: CBService, error _: Error?) {
    didAddService = true
    manager.startAdvertising([
      CBAdvertisementDataServiceUUIDsKey: [BluetoothConstants.service],
      CBAdvertisementDataLocalNameKey: "Pigeon",
    ])
    note("Advertising")
  }

  func peripheralManager(_ manager: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
    for request in requests {
      if let value = request.value {
        note("write-recv \(value.count)B")
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
    if !subscribedCentrals.contains(where: { $0.identifier == central.identifier }) {
      subscribedCentrals.append(central)
    }
    note("Central \(central.identifier.uuidString.prefix(8)) subscribed")
  }

  func peripheralManager(
    _: CBPeripheralManager, central: CBCentral,
    didUnsubscribeFrom _: CBCharacteristic
  ) {
    subscribedCentrals.removeAll { $0.identifier == central.identifier }
  }
}
