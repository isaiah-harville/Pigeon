import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class GroupRelayProtocolTests: XCTestCase {
  private let coordinationID = Data((0..<32).map(UInt8.init))

  func testGroupEndpointUsesTheSelectedRelayHost() {
    XCTAssertEqual(
      GroupRelayTransport.endpoint(for: URL(string: "https://relay.example/ws")),
      URL(string: "wss://relay.example/group/ws"))
    XCTAssertEqual(
      GroupRelayTransport.endpoint(for: URL(string: "wss://relay.example/custom")),
      URL(string: "wss://relay.example/group/ws"))
    XCTAssertNil(GroupRelayTransport.endpoint(for: URL(string: "file:///tmp/relay")))
  }

  func testClientFramesMatchRelayVersionSevenWireFormat() throws {
    XCTAssertEqual(
      try object(GroupRelayProtocol.hello()),
      ["type": "hello", "min_protocol_version": 7, "max_protocol_version": 7])

    let registration = PigeonGroupRelayRegistration(
      coordinationID: coordinationID,
      capabilities: [
        PigeonGroupRelayCapability(
          capabilityID: Data(repeating: 6, count: 32),
          publicKey: Data(repeating: 7, count: 32), canAppend: true,
          canRead: true, canControl: true)
      ],
      signature: Data(repeating: 8, count: 64), authorizationGeneration: 3,
      permanentControllerPublicKey: Data(repeating: 7, count: 32))
    let register = try object(GroupRelayProtocol.register(registration))
    XCTAssertEqual(register["type"] as? String, "register")
    XCTAssertEqual(register["coordination_id"] as? String, coordinationID.hexEncoded)
    XCTAssertEqual(register["signature"] as? String, registration.signature.base64EncodedString())
    XCTAssertEqual(register["authorization_generation"] as? UInt64, 3)
    XCTAssertNil(register["admission_solution"])
    let challenge = Data(repeating: 9, count: 32)
    let transcript = try GroupRegistrationAdmission.transcript(registration)
    let solution = try GroupRegistrationAdmission.solve(
      transcript: transcript, challenge: challenge, difficulty: 8)
    XCTAssertEqual(solution.count, 8)
    var proof = Data("pigeon.relay.group.admission.v1".utf8)
    proof.append(challenge)
    proof.append(contentsOf: SHA256.hash(data: transcript))
    proof.append(solution)
    XCTAssertEqual(Array(SHA256.hash(data: proof))[0], 0)
    XCTAssertEqual(
      try object(GroupRelayProtocol.register(registration, admissionSolution: solution))[
        "admission_solution"] as? String,
      solution.base64EncodedString())

    XCTAssertEqual(
      try object(
        GroupRelayProtocol.authenticate(
          coordinationID: coordinationID,
          capabilityID: Data(repeating: 9, count: 32))),
      [
        "type": "authenticate", "coordination_id": coordinationID.hexEncoded,
        "capability_id": Data(repeating: 9, count: 32).hexEncoded,
      ])
    XCTAssertEqual(
      try object(GroupRelayProtocol.auth(signature: Data([1, 2]))),
      ["type": "auth", "signature": "AQI="])
    XCTAssertEqual(
      try object(GroupRelayProtocol.coordinatorKey()),
      ["type": "coordinator_key"])
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
              coordinationID: coordinationID, kind: .replaceAll, publicKey: Data(),
              capabilities: [
                PigeonGroupRelayCapability(
                  capabilityID: Data(repeating: 10, count: 32),
                  publicKey: Data(repeating: 4, count: 32), canAppend: true,
                  canRead: true, canControl: true)
              ], expectedGeneration: 4, newGeneration: 5,
              permanentControllerPublicKey: Data(repeating: 4, count: 32))))),
      [
        "type": "replace_capabilities", "expected_generation": 4,
        "new_generation": 5,
        "permanent_controller_public_key": Data(repeating: 4, count: 32).hexEncoded,
        "capabilities": [
          [
            "capability_id": Data(repeating: 10, count: 32).hexEncoded,
            "public_key": Data(repeating: 4, count: 32).hexEncoded,
            "can_append": true, "can_read": true, "can_control": true,
          ]
        ],
      ])
    XCTAssertEqual(
      try object(
        GroupRelayProtocol.action(
          .control(
            PigeonGroupRelayControl(
              coordinationID: coordinationID, kind: .revokeAll, publicKey: Data(),
              capabilities: [], expectedGeneration: 5, newGeneration: 6,
              permanentControllerPublicKey: Data(repeating: 4, count: 32))))),
      ["type": "revoke_group", "expected_generation": 5])
    XCTAssertEqual(
      try object(
        GroupRelayProtocol.action(
          .coordinatorSubmission(
            PigeonGroupCoordinatorSubmission(
              coordinationID: coordinationID, claimedBaseEpoch: 6,
              candidate: Data([5, 6]))))),
      ["type": "coordinator_submit", "claimed_base_epoch": 6, "candidate": "BQY="])
    XCTAssertEqual(
      try object(GroupRelayProtocol.coordinatorFetch(after: 12)),
      ["type": "coordinator_fetch", "after_sequence": 12])
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
    XCTAssertEqual(
      GroupRelayProtocol.classify([
        "type": "registration_challenge",
        "nonce": Data(repeating: 2, count: 32).base64EncodedString(),
        "difficulty": 18,
      ]),
      .registrationChallenge(nonce: Data(repeating: 2, count: 32), difficulty: 18))
    XCTAssertEqual(GroupRelayProtocol.classify(["type": "future"]), .ignored)
    XCTAssertEqual(
      GroupRelayProtocol.classify([
        "type": "coordinator_key",
        "public_key": Data(repeating: 9, count: 32).hexEncoded,
      ]),
      .coordinatorKey(Data(repeating: 9, count: 32)))
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

  func testReplacementConnectionConfirmsAuthorizationOnceItBecomesCanonical() {
    var state = GroupRelayAuthorizationState(requiresConfirmation: false)
    var confirmations = 0

    XCTAssertTrue(
      state.confirmIfRequired {
        confirmations += 1
        return true
      })
    XCTAssertEqual(confirmations, 0)

    state.requireConfirmation()
    XCTAssertTrue(
      state.confirmIfRequired {
        confirmations += 1
        return true
      })
    XCTAssertTrue(
      state.confirmIfRequired {
        confirmations += 1
        return true
      })
    XCTAssertEqual(confirmations, 1)
  }

  func testProtocolVersionRejectsOutOfRangeAndFractionalJSONIntegers() throws {
    for literal in ["9223372036854775808", "18446744073709551615", "1.5", "true"] {
      let frame = try decodedFrame("{\"type\":\"compatible\",\"protocol_version\":\(literal)}")
      XCTAssertEqual(frame, .ignored, literal)
    }
    XCTAssertEqual(
      try decodedFrame("{\"type\":\"compatible\",\"protocol_version\":9223372036854775807}"),
      .compatible(protocolVersion: Int.max, relayVersion: nil))
  }

  func testSequenceRejectsOutOfRangeAndFractionalJSONIntegers() throws {
    for literal in ["18446744073709551616", "0.5", "true"] {
      XCTAssertEqual(
        try decodedFrame("{\"type\":\"appended\",\"sequence\":\(literal)}"),
        .ignored, literal)
    }
    XCTAssertEqual(
      try decodedFrame("{\"type\":\"appended\",\"sequence\":18446744073709551615}"),
      .appended(sequence: UInt64.max))
  }

  func testEntryCountAndMalformedResponsesFailExplicitly() throws {
    let entry: [String: Any] = ["sequence": 1, "timestamp": 1, "ciphertext": "AQ=="]
    XCTAssertNotEqual(
      GroupRelayProtocol.classify([
        "type": "entries", "entries": Array(repeating: entry, count: 512),
      ]),
      .ignored)
    XCTAssertEqual(
      GroupRelayProtocol.classify([
        "type": "entries", "entries": Array(repeating: entry, count: 513),
      ]),
      .ignored)
    XCTAssertThrowsError(
      try GroupRelaySocket.decode(Data("{\"type\":\"entries\",\"entries\":{}}".utf8)))
    XCTAssertThrowsError(
      try GroupRelaySocket.decode(
        Data(
          "{\"type\":\"wake\",\"padding\":\"\(String(repeating: "x", count: 2 * 1024 * 1024))\"}"
            .utf8)))
  }

  func testConnectionDrainsAnotherMessagePageAfterDurableAdvance() {
    let connection = GroupRelayConnection(group: testGroup())
    connection.ready = true
    connection.fetchedAfterConnect = true
    connection.scheduleNextMessagePage(after: 5)
    XCTAssertEqual(connection.queue, [.advance(5), .fetchMessages])
  }

  private func decodedFrame(_ json: String) throws -> GroupRelayProtocol.ServerFrame {
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    return GroupRelayProtocol.classify(object)
  }

  private func testGroup() -> PigeonGroupState {
    PigeonGroupState(
      groupID: coordinationID, ownerIdentity: coordinationID,
      adminIdentities: [], memberIdentities: [], name: "test",
      relayURL: "https://relay.example", coordinationID: coordinationID,
      meshEnabled: false, epoch: 1, policyRevision: 1, dissolved: false,
      capabilityPublicKey: coordinationID, capabilityID: coordinationID,
      coordinatorPublicKey: coordinationID, coordinatorSequence: 0)
  }

  private func object(_ data: Data) throws -> NSDictionary {
    try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? NSDictionary)
  }
}
