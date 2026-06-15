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
//  v1 limitations (tracked): uses write-with-response (reliable but slower)
//  and a conservative fixed fragment size; if two devices connect to each other
//  in both roles, a message may be delivered twice — the mesh dedup layer
//  (Phase 4) will absorb duplicates.
//

import Foundation
import CoreBluetooth
import PigeonMesh

/// Drives Bluetooth discovery and messaging and publishes observable state for
/// the UI. Runs on the main actor; CoreBluetooth callbacks are delivered on the
/// main queue.
@MainActor
@Observable
final class PeerTransport: NSObject {

    /// Human-readable radio state for the UI.
    enum Status: String {
        case idle = "Idle"
        case unauthorized = "Bluetooth not authorized"
        case poweredOff = "Bluetooth is off"
        case scanning = "Scanning for peers…"
    }

    private(set) var status: Status = .idle
    /// Number of peers we are currently connected to (as central).
    private(set) var connectedPeerCount = 0
    /// Recent activity, newest last — purely for the Phase 3 test UI.
    private(set) var log: [String] = []

    /// Invoked with each fully reassembled inbound message and its source id.
    var onMessage: ((_ message: Data, _ peerID: String) -> Void)?

    private var central: CBCentralManager!
    private var peripheralManager: CBPeripheralManager!

    // Peripheral (server) side.
    private var outboundCharacteristic: CBMutableCharacteristic?
    private var subscribedCentrals: [CBCentral] = []

    // Central (client) side: retained connections and their inbound characteristic.
    private var peripherals: [UUID: CBPeripheral] = [:]
    private var inboundCharacteristics: [UUID: CBCharacteristic] = [:]

    // Outbound fragmenter + per-source reassemblers.
    private var fragmenter = Fragmenter()
    private var reassemblers: [UUID: Reassembler] = [:]

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)
        peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
    }

    /// Broadcasts `message` to every connected peer, in both roles.
    func broadcast(_ message: Data) {
        let fragments: [Fragment]
        do {
            fragments = try fragmenter.fragment(message, maxPayloadPerFragment: BluetoothConstants.maxFragmentPayload)
        } catch {
            note("Failed to fragment message: \(error)")
            return
        }

        for fragment in fragments {
            let bytes = fragment.encoded()

            // Central path: write to each connected peripheral's inbound characteristic.
            for (id, peripheral) in peripherals {
                if let characteristic = inboundCharacteristics[id] {
                    peripheral.writeValue(bytes, for: characteristic, type: .withResponse)
                }
            }

            // Peripheral path: notify subscribed centrals via outbound characteristic.
            if let characteristic = outboundCharacteristic, !subscribedCentrals.isEmpty {
                peripheralManager.updateValue(bytes, for: characteristic, onSubscribedCentrals: nil)
            }
        }
        note("Sent \(message.count)B in \(fragments.count) fragment(s)")
    }

    // MARK: - Helpers

    private func note(_ message: String) {
        log.append(message)
        if log.count > 200 { log.removeFirst(log.count - 200) }
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
        central.scanForPeripherals(withServices: [BluetoothConstants.service],
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

    func centralManager(_ manager: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard peripherals[peripheral.identifier] == nil else { return }
        peripherals[peripheral.identifier] = peripheral // retain before connecting
        note("Discovered peer \(peripheral.identifier.uuidString.prefix(8))")
        manager.connect(peripheral, options: nil)
    }

    func centralManager(_ manager: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheral.delegate = self
        peripheral.discoverServices([BluetoothConstants.service])
        connectedPeerCount = peripherals.count
        note("Connected to \(peripheral.identifier.uuidString.prefix(8))")
    }

    func centralManager(_ manager: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        peripherals[peripheral.identifier] = nil
        inboundCharacteristics[peripheral.identifier] = nil
        reassemblers[peripheral.identifier] = nil
        connectedPeerCount = peripherals.count
        note("Disconnected \(peripheral.identifier.uuidString.prefix(8))")
        startScanningIfReady()
    }

    func centralManager(_ manager: CBCentralManager, didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        peripherals[peripheral.identifier] = nil
        note("Failed to connect \(peripheral.identifier.uuidString.prefix(8))")
    }
}

// MARK: - CBPeripheralDelegate (central-side: talking to a remote peripheral)

extension PeerTransport: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        for service in peripheral.services ?? [] where service.uuid == BluetoothConstants.service {
            peripheral.discoverCharacteristics([BluetoothConstants.inbound, BluetoothConstants.outbound],
                                               for: service)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        for characteristic in service.characteristics ?? [] {
            switch characteristic.uuid {
            case BluetoothConstants.inbound:
                inboundCharacteristics[peripheral.identifier] = characteristic
            case BluetoothConstants.outbound:
                peripheral.setNotifyValue(true, for: characteristic) // receive peer → us
            default:
                break
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard let data = characteristic.value else { return }
        receive(data, from: peripheral.identifier)
    }
}

// MARK: - CBPeripheralManagerDelegate (peripheral-side: serving remote centrals)

extension PeerTransport: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ manager: CBPeripheralManager) {
        guard manager.state == .poweredOn else { return }

        let inbound = CBMutableCharacteristic(type: BluetoothConstants.inbound,
                                              properties: [.write],
                                              value: nil,
                                              permissions: [.writeable])
        let outbound = CBMutableCharacteristic(type: BluetoothConstants.outbound,
                                               properties: [.notify],
                                               value: nil,
                                               permissions: [.readable])
        outboundCharacteristic = outbound

        let service = CBMutableService(type: BluetoothConstants.service, primary: true)
        service.characteristics = [inbound, outbound]
        manager.add(service)
    }

    func peripheralManager(_ manager: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        manager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [BluetoothConstants.service],
            CBAdvertisementDataLocalNameKey: "Pigeon",
        ])
        note("Advertising")
    }

    func peripheralManager(_ manager: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            if let value = request.value {
                receive(value, from: request.central.identifier)
            }
        }
        if let first = requests.first {
            manager.respond(to: first, withResult: .success)
        }
    }

    func peripheralManager(_ manager: CBPeripheralManager, central: CBCentral,
                           didSubscribeTo characteristic: CBCharacteristic) {
        if !subscribedCentrals.contains(where: { $0.identifier == central.identifier }) {
            subscribedCentrals.append(central)
        }
        note("Central \(central.identifier.uuidString.prefix(8)) subscribed")
    }

    func peripheralManager(_ manager: CBPeripheralManager, central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        subscribedCentrals.removeAll { $0.identifier == central.identifier }
    }
}
