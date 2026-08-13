//
//  DiagnosticEvent.swift
//  Pigeon
//

import Foundation

/// Closed, identifier-free events allowed in the in-app diagnostic buffer.
/// Cases intentionally carry no associated values: display names, peer ids,
/// relay hosts, payload sizes, and underlying error strings cannot enter logs.
enum DiagnosticEvent: CaseIterable {
  case sessionEstablished
  case sessionRejected
  case decryptionFailed
  case reestablishmentRequested
  case missingPrekey
  case firstContactFailed
  case firstContactStarted
  case refreshingChats
  case backgroundSettingFailed
  case manualRetry
  case persistenceFailed
  case signedPrekeyRotated
  case ownIdentityScanned
  case contactAdded
  case messageQueued
  case fragmentationFailed
  case transportBroadcast
  case transportNoPath
  case transportRefresh
  case transportReceived
  case malformedFragment
  case transportScanning
  case transportRestored
  case peerDiscovered
  case peerConnected
  case peerDisconnected
  case peerConnectionFailed
  case writeChannelReady
  case peerSubscribed
  case transportAdvertising
  case relayOffline
  case relayReady
  case relayError
  case networkRestored
  case wifiReady
  case wifiSendFailed

  var message: String {
    switch self {
    case .sessionEstablished: "Secure session established"
    case .sessionRejected: "Secure session rejected"
    case .decryptionFailed: "Message decryption failed; re-establishing"
    case .reestablishmentRequested: "Peer requested session re-establishment"
    case .missingPrekey: "Contact has no usable prekey"
    case .firstContactFailed: "First contact failed"
    case .firstContactStarted: "First contact started"
    case .refreshingChats: "Refreshing chats"
    case .backgroundSettingFailed: "Background-delivery setting failed"
    case .manualRetry: "Manual delivery retry"
    case .persistenceFailed: "Encrypted-store save failed"
    case .signedPrekeyRotated: "Signed prekey rotated"
    case .ownIdentityScanned: "Own identity code rejected"
    case .contactAdded: "Contact added"
    case .messageQueued: "Message queued until connected"
    case .fragmentationFailed: "Transport fragmentation failed"
    case .transportBroadcast: "Transport broadcast completed"
    case .transportNoPath: "Transport broadcast has no active path"
    case .transportRefresh: "Transport refresh requested"
    case .transportReceived: "Transport data received"
    case .malformedFragment: "Malformed transport fragment rejected"
    case .transportScanning: "Transport scanning"
    case .transportRestored: "Transport state restored"
    case .peerDiscovered: "Peer discovered"
    case .peerConnected: "Peer connected"
    case .peerDisconnected: "Peer disconnected"
    case .peerConnectionFailed: "Peer connection failed"
    case .writeChannelReady: "Peer write channel ready"
    case .peerSubscribed: "Peer subscribed"
    case .transportAdvertising: "Transport advertising"
    case .relayOffline: "Relay offline; retrying"
    case .relayReady: "Relay connection ready"
    case .relayError: "Relay returned an error"
    case .networkRestored: "Network restored; reconnecting relays"
    case .wifiReady: "Local Wi-Fi discovery ready"
    case .wifiSendFailed: "Local Wi-Fi send failed"
    }
  }

  var isReleaseVisible: Bool {
    switch self {
    case .sessionRejected, .decryptionFailed, .missingPrekey, .firstContactFailed,
      .backgroundSettingFailed, .persistenceFailed, .fragmentationFailed,
      .malformedFragment, .relayError, .wifiSendFailed:
      true
    default:
      false
    }
  }
}

enum DiagnosticLog {
  static func record(_ event: DiagnosticEvent, in lines: inout [String], limit: Int) {
    #if DEBUG
      lines.append(event.message)
    #else
      guard event.isReleaseVisible else { return }
      lines.append(event.message)
    #endif
    if lines.count > limit { lines.removeFirst(lines.count - limit) }
  }
}
