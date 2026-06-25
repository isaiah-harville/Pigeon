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

  /// Conservative per-fragment payload **floor** (bytes). Kept well under the
  /// minimum negotiated BLE ATT payload so a fragment always fits in one
  /// write/notification on any link. The transport now raises the budget per
  /// connection from the negotiated MTU; this stays the safe lower bound we
  /// never drop below, so behaviour on an un-upgraded link is unchanged.
  static let maxFragmentPayload = 150

  /// Per-fragment payload **ceiling** (bytes). The negotiated-MTU budget is
  /// clamped here so an unusually large reported length can't push a fragment past
  /// a size that stays within a single BLE notification PDU on current iOS
  /// (ATT MTUs negotiate up to ~517 bytes). The per-link minimum is the real cap;
  /// this is a defensive bound.
  static let maxFragmentPayloadCeiling = 503

  /// Bytes the `pigeon-mesh` fragmenter prepends to every fragment payload
  /// (`version‖messageID‖index‖count`). Mirrors `HEADER_SIZE` in
  /// `pigeon-mesh/src/fragment.rs` — a stable, versioned wire constant — and is
  /// subtracted from a link's negotiated value length to get the usable payload.
  static let fragmentHeaderSize = 7
}
