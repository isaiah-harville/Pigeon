//
//  RelayProtocol.swift
//  Pigeon
//

import Foundation

enum RelayError: Error {
  case handshake
  case incompatible
  case protocolError
}

extension RelayTransport {

  static let minimumProtocolVersion = 1
  static let maximumProtocolVersion = 1

  static func selectProtocol(serverMinimum: Int, serverMaximum: Int) -> Int? {
    guard serverMinimum <= serverMaximum else { return nil }
    let minimum = max(minimumProtocolVersion, serverMinimum)
    let maximum = min(maximumProtocolVersion, serverMaximum)
    return minimum <= maximum ? maximum : nil
  }

  static func advertisedRelays(configured: [URL], excluding incompatible: Set<URL>) -> [URL] {
    configured.filter { !incompatible.contains($0) }
  }

  /// Where to deposit ciphertext for a recipient: the relays they advertise.
  static func deliveryTargets(advertised: [URL]) -> [URL] {
    deliveryTargets(preferred: nil, advertised: advertised)
  }

  /// Orders an advertised preferred relay first, with the rest as fallbacks.
  static func deliveryTargets(preferred: URL?, advertised: [URL]) -> [URL] {
    guard let preferred, advertised.contains(preferred) else { return advertised }
    return [preferred] + advertised.filter { $0 != preferred }
  }

  /// The de-duplicated union of our receiving relays and contact deposit relays.
  static func wantedConnections(myRelays: [URL], contactRelays: [URL]) -> [URL] {
    var wanted: [URL] = []
    for url in myRelays + contactRelays where !wanted.contains(url) { wanted.append(url) }
    return wanted
  }

  /// A classified inbound server frame. Malformed and unknown frames are ignored.
  enum InboundFrame: Equatable {
    case envelope(Envelope)
    case error(String)
    case ignored

    struct Envelope: Equatable {
      let id: String
      let ciphertext: Data
    }
  }

  static func classifyInbound(_ message: [String: Any]) -> InboundFrame {
    switch message["type"] as? String {
    case "envelope":
      guard let id = message["id"] as? String,
        let ciphertextB64 = message["ciphertext"] as? String,
        let data = Data(base64Encoded: ciphertextB64)
      else { return .ignored }
      return .envelope(InboundFrame.Envelope(id: id, ciphertext: data))
    case "error":
      return .error(message["message"] as? String ?? "error")
    default:
      return .ignored
    }
  }
}
