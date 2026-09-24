import Foundation

extension GroupRelayProtocol {
  struct Entry: Equatable, Sendable {
    let sequence: UInt64
    let ciphertext: Data
    let timestamp: UInt64
  }

  struct CoordinatorReceipt: Equatable, Sendable {
    let coordinationID: Data
    let sequence: UInt64
    let priorReceiptHash: Data
    let claimedBaseEpoch: UInt64
    let entryHash: Data
    let signature: Data
  }

  struct CoordinatorCandidate: Equatable, Sendable {
    let receipt: CoordinatorReceipt
    let candidate: Data
    let timestamp: UInt64
  }

  enum ServerFrame: Equatable, Sendable {
    case compatible(protocolVersion: Int, relayVersion: String?)
    case incompatible(protocolVersion: Int, relayVersion: String?)
    case challenge(Data)
    case registered
    case appended(sequence: UInt64)
    case entries([Entry])
    case wake
    case ok
    case error(String)
    case coordinatorKey(Data)
    case coordinatorReceipt(CoordinatorReceipt)
    case coordinatorCandidates([CoordinatorCandidate])
    case ignored
  }
}
