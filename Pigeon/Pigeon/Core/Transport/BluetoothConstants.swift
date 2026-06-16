//
//  BluetoothConstants.swift
//  Pigeon
//
//  Fixed identifiers for Pigeon's custom GATT service.
//

import CoreBluetooth

/// Pigeon's BLE service and characteristic UUIDs. All Pigeon devices advertise
/// and scan for `service`; two characteristics carry fragmented traffic in each
/// direction over a single central↔peripheral connection.
enum BluetoothConstants {
  /// Service advertised by every Pigeon device.
  static let service = CBUUID(string: "9E7B0001-8F2A-4C3D-9A1B-2E5F7C8D0A10")

  /// Central → peripheral. A connected central writes outbound fragments here.
  static let inbound = CBUUID(string: "9E7B0002-8F2A-4C3D-9A1B-2E5F7C8D0A10")

  /// Peripheral → central. The peripheral notifies subscribed centrals with
  /// fragments on this characteristic.
  static let outbound = CBUUID(string: "9E7B0003-8F2A-4C3D-9A1B-2E5F7C8D0A10")

  /// Conservative per-fragment payload budget (bytes). Kept well under the
  /// minimum negotiated BLE ATT payload so a fragment always fits in one
  /// write/notification regardless of the peer's MTU. Future work: raise this
  /// per connection using the negotiated MTU.
  static let maxFragmentPayload = 150
}
