import Foundation
import PigeonFFI

extension GroupRelayTransport {
  static func endpoint(for relayURL: URL?) -> URL? {
    guard let relayURL,
      var components = URLComponents(
        url: relayURL,
        resolvingAgainstBaseURL: false),
      components.user == nil, components.password == nil, components.fragment == nil
    else { return nil }
    switch components.scheme?.lowercased() {
    case "https": components.scheme = "wss"
    case "http": components.scheme = "ws"
    case "wss", "ws": break
    default: return nil
    }
    guard components.host != nil else { return nil }
    components.path = "/group/ws"
    components.query = nil
    return components.url
  }
}

extension GroupRelayProtocol.CoordinatorReceipt {
  var publicValue: PigeonCoordinatorReceipt {
    PigeonCoordinatorReceipt(
      coordinationID: coordinationID, sequence: sequence,
      priorReceiptHash: priorReceiptHash, claimedBaseEpoch: claimedBaseEpoch,
      entryHash: entryHash, signature: signature)
  }
}
