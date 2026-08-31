import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class GroupRelayProtocolTests: XCTestCase {
  private let coordinationID = Data((0..<32).map(UInt8.init))

  func testClientFramesMatchRelayVersionFourWireFormat() throws {
    XCTAssertEqual(
      try object(GroupRelayProtocol.hello()),
      ["type": "hello", "min_protocol_version": 4, "max_protocol_version": 4])

    let registration = PigeonGroupRelayRegistration(
      coordinationID: coordinationID,
      capabilities: [
        PigeonGroupRelayCapability(
          publicKey: Data(repeating: 7, count: 32), canAppend: true,
          canRead: true, canControl: true)
      ],
      signature: Data(repeating: 8, count: 64))
    let register = try object(GroupRelayProtocol.register(registration))
    XCTAssertEqual(register["type"] as? String, "register")
    XCTAssertEqual(register["coordination_id"] as? String, coordinationID.hexEncoded)
    XCTAssertEqual(register["signature"] as? String, registration.signature.base64EncodedString())

    XCTAssertEqual(
      try object(
        GroupRelayProtocol.authenticate(
          coordinationID: coordinationID,
          capabilityKey: Data(repeating: 9, count: 32))),
      [
        "type": "authenticate", "coordination_id": coordinationID.hexEncoded,
        "capability_key": Data(repeating: 9, count: 32).hexEncoded,
      ])
    XCTAssertEqual(
      try object(GroupRelayProtocol.auth(signature: Data([1, 2]))),
      ["type": "auth", "signature": "AQI="])
  }

  func testCoreRelayActionsEncodeWithoutExposingProtobufToTransport() throws {
    XCTAssertEqual(
      try object(
        GroupRelayProtocol.action(
          .append(
            PigeonGroupRelayAppend(
              coordinationID: coordinationID, ciphertext: Data([1, 2, 3]))))),
      ["type": "append", "ciphertext": "AQID"])
    XCTAssertEqual(
      try object(
        GroupRelayProtocol.action(
          .control(
            PigeonGroupRelayControl(
              coordinationID: coordinationID, kind: .promoteAdmin,
              publicKey: Data(repeating: 4, count: 32))))),
      [
        "type": "update", "public_key": Data(repeating: 4, count: 32).hexEncoded,
        "can_control": true,
      ])
    XCTAssertEqual(
      try object(
        GroupRelayProtocol.action(
          .coordinatorSubmission(
            PigeonGroupCoordinatorSubmission(
              coordinationID: coordinationID, claimedBaseEpoch: 6,
              candidate: Data([5, 6]))))),
      ["type": "coordinator_submit", "claimed_base_epoch": 6, "candidate": "BQY="])
    XCTAssertEqual(
      try object(
        GroupRelayProtocol.action(
          .coordinatorFetch(
            PigeonGroupCoordinatorFetch(
              coordinationID: coordinationID, groupID: Data(repeating: 1, count: 32),
              fromEpoch: 7, throughEpoch: 9)))),
      ["type": "coordinator_fetch", "after_sequence": 6])
  }

  func testServerFramesAreStrictlyClassifiedAndBounded() {
    XCTAssertEqual(
      GroupRelayProtocol.classify([
        "type": "challenge",
        "nonce": Data(repeating: 1, count: 32)
          .base64EncodedString(),
      ]),
      .challenge(Data(repeating: 1, count: 32)))
    XCTAssertEqual(
      GroupRelayProtocol.classify([
        "type": "entries",
        "entries": [["sequence": 3, "ciphertext": "AQI=", "timestamp": 10]],
      ]),
      .entries([.init(sequence: 3, ciphertext: Data([1, 2]), timestamp: 10)]))
    XCTAssertEqual(
      GroupRelayProtocol.classify(["type": "challenge", "nonce": "AQI="]),
      .ignored)
    XCTAssertEqual(GroupRelayProtocol.classify(["type": "future"]), .ignored)
  }

  func testCoordinatorCandidatesDecodeAllAuthenticatedReceiptFields() {
    let receipt: [String: Any] = [
      "coordination_id": coordinationID.hexEncoded,
      "sequence": 2,
      "prior_receipt_hash": Data(repeating: 3, count: 32).hexEncoded,
      "claimed_base_epoch": 1,
      "entry_hash": Data(repeating: 4, count: 32).hexEncoded,
      "signature": Data(repeating: 5, count: 64).base64EncodedString(),
    ]

    XCTAssertEqual(
      GroupRelayProtocol.classify([
        "type": "coordinator_candidates",
        "candidates": [["receipt": receipt, "candidate": "AQI=", "timestamp": 9]],
      ]),
      .coordinatorCandidates([
        .init(
          receipt: .init(
            coordinationID: coordinationID, sequence: 2,
            priorReceiptHash: Data(repeating: 3, count: 32), claimedBaseEpoch: 1,
            entryHash: Data(repeating: 4, count: 32),
            signature: Data(repeating: 5, count: 64)),
          candidate: Data([1, 2]), timestamp: 9)
      ]))
  }

  private func object(_ data: Data) throws -> NSDictionary {
    try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? NSDictionary)
  }
}
