import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class PairwiseRelayProtocolTests: XCTestCase {
  func testPublishWrapsOpaqueCorePayloadInAddressedPairwiseEnvelope() throws {
    let sender = Data(repeating: 1, count: 32)
    let recipient = Data(repeating: 2, count: 32)
    let payload = Data([3, 4, 5])

    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(
        with: try PairwiseRelayProtocol.publish(
          sender: sender, recipient: recipient, payload: payload)) as? [String: String])

    XCTAssertEqual(object["type"], "publish")
    XCTAssertEqual(object["recipient"], recipient.hexEncoded)
    let encodedCiphertext = try XCTUnwrap(object["ciphertext"])
    let ciphertext = try XCTUnwrap(Data(base64Encoded: encodedCiphertext))
    let envelope = try SessionEnvelope(decoding: ciphertext)
    XCTAssertEqual(envelope.type, EnvelopeType.pairwise)
    XCTAssertEqual(envelope.sender, sender)
    XCTAssertEqual(envelope.recipient, recipient)
    XCTAssertEqual(envelope.payload, payload)
  }

  func testPublishRejectsMalformedRoutingFields() {
    XCTAssertThrowsError(
      try PairwiseRelayProtocol.publish(
        sender: Data(repeating: 1, count: 31),
        recipient: Data(repeating: 2, count: 32), payload: Data([3])))
    XCTAssertThrowsError(
      try PairwiseRelayProtocol.publish(
        sender: Data(repeating: 1, count: 32),
        recipient: Data(repeating: 2, count: 32), payload: Data()))
  }

  func testPublishedConfirmationIsStrictlyClassified() {
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "published", "id": "42"]), .published)
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "error"]), .error)
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "future"]), .ignored)
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "published"]), .ignored)
  }

  func testDeliveryQueueRetriesUntilDurableCoreAcknowledgement() {
    let first = PairwiseRelayEffect(
      id: "first", recipient: Data(repeating: 1, count: 32), payload: Data([2]))
    let second = PairwiseRelayEffect(
      id: "second", recipient: Data(repeating: 3, count: 32), payload: Data([4]))
    var queue = PairwiseRelayDeliveryQueue()
    queue.reconcile([first, second])

    XCTAssertEqual(queue.next(), first)
    XCTAssertFalse(queue.confirm { _ in false })
    queue.retryAwaiting()
    XCTAssertEqual(queue.next(), first)
    XCTAssertTrue(queue.confirm { $0 == "first" })
    XCTAssertEqual(queue.next(), second)
  }
}
