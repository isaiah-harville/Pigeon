import Foundation

public struct PigeonAcknowledgeEffects: Equatable, Sendable {
  public let outboundItemIDs: [String]
  public let eventIDs: [String]

  public init(outboundItemIDs: [String] = [], eventIDs: [String] = []) {
    self.outboundItemIDs = outboundItemIDs
    self.eventIDs = eventIDs
  }
}
