import CoreBluetooth
import Foundation
import PigeonFFI

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

  func installPeripheralServiceIfReady() {
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
