import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class PairwiseRelayProtocolTests: XCTestCase {
  func testPublishedPairwisePayloadCanPassThroughMeshReceiver() throws {
    let sender = Data(repeating: 1, count: 32)
    let recipient = Data(repeating: 2, count: 32)
    let payload = Data([3, 4, 5])

    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(
        with: try PairwiseRelayProtocol.publish(
          sender: sender, recipient: recipient, payload: payload, requestID: nil))
        as? [String: String])

    XCTAssertEqual(object["type"], "publish")
    XCTAssertEqual(object["recipient"], recipient.hexEncoded)
    let encodedCiphertext = try XCTUnwrap(object["ciphertext"])
    let ciphertext = try XCTUnwrap(Data(base64Encoded: encodedCiphertext))
    let packet = try MeshPacket(decoding: ciphertext)
    let reception = MeshRouter().ingest(packet)
    XCTAssertNil(reception.relay)
    let envelope = try SessionEnvelope(decoding: XCTUnwrap(reception.deliver))
    XCTAssertEqual(envelope.type, EnvelopeType.pairwise)
    XCTAssertEqual(envelope.sender, sender)
    XCTAssertEqual(envelope.recipient, recipient)
    XCTAssertEqual(envelope.payload, payload)
  }

  func testPublishRejectsMalformedRoutingFields() {
    XCTAssertThrowsError(
      try PairwiseRelayProtocol.publish(
        sender: Data(repeating: 1, count: 31),
        recipient: Data(repeating: 2, count: 32), payload: Data([3]), requestID: nil))
    XCTAssertThrowsError(
      try PairwiseRelayProtocol.publish(
        sender: Data(repeating: 1, count: 32),
        recipient: Data(repeating: 2, count: 32), payload: Data(), requestID: nil))
  }

  func testPublishedConfirmationIsStrictlyClassified() {
    XCTAssertEqual(
      PairwiseRelayProtocol.classify(["type": "published", "id": "42"]),
      .published(requestID: nil))
    XCTAssertEqual(
      PairwiseRelayProtocol.classify(["type": "published", "id": "42", "request_id": "a"]),
      .published(requestID: "a"))
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "error"]), .refused(requestID: nil))
    XCTAssertEqual(
      PairwiseRelayProtocol.classify(["type": "error", "request_id": "b"]),
      .refused(requestID: "b"))
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "future"]), .ignored)
    XCTAssertEqual(PairwiseRelayProtocol.classify(["type": "published"]), .ignored)
  }

  func testPublishCarriesTheRequestID() throws {
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(
        with: try PairwiseRelayProtocol.publish(
          sender: Data(repeating: 1, count: 32), recipient: Data(repeating: 2, count: 32),
          payload: Data([3]), requestID: "item-1")) as? [String: String])
    XCTAssertEqual(object["request_id"], "item-1")
  }

  func testRequestIDStaysWithinRelayLimits() {
    let short = effect("send:1:pairwise")
    XCTAssertEqual(short.requestID, "send:1:pairwise")
    let long = effect(String(repeating: "x", count: 200))
    XCTAssertEqual(long.requestID.count, 64)
    XCTAssertTrue(long.requestID.allSatisfy(\.isASCII))
    XCTAssertEqual(effect("café").requestID.count, 64)
  }

  func testDeliveryQueueRetriesUntilDurableCoreAcknowledgement() {
    let now = ContinuousClock.now
    let first = effect("first")
    let second = effect("second")
    var queue = PairwiseRelayDeliveryQueue()
    queue.reconcile([first, second])

    XCTAssertEqual(queue.next(now: now), first)
    XCTAssertEqual(queue.next(now: now), second)
    XCTAssertFalse(queue.confirm(requestID: "first") { _ in false })
    queue.retryInFlight()
    XCTAssertEqual(queue.next(now: now), first)
    XCTAssertEqual(queue.next(now: now), second)
    XCTAssertTrue(queue.confirm(requestID: "second") { $0 == "second" })
    XCTAssertTrue(queue.confirm(requestID: "first") { $0 == "first" })
    XCTAssertTrue(queue.isEmpty)
  }

  func testDeliveryQueuePipelinesUpToItsWindow() {
    let now = ContinuousClock.now
    let effects = (0..<(PairwiseRelayDeliveryQueue.window + 3)).map { effect("item-\($0)") }
    var queue = PairwiseRelayDeliveryQueue()
    queue.reconcile(effects)

    var sent: [PairwiseRelayEffect] = []
    while let next = queue.next(now: now) { sent.append(next) }
    XCTAssertEqual(sent, Array(effects.prefix(PairwiseRelayDeliveryQueue.window)))
    XCTAssertTrue(queue.confirm(requestID: "item-0") { _ in true })
    XCTAssertEqual(queue.next(now: now), effects[PairwiseRelayDeliveryQueue.window])
  }

  func testRefusedDepositDoesNotBlockLaterDeposits() {
    let now = ContinuousClock.now
    let refused = effect("refused")
    let later = effect("later")
    var queue = PairwiseRelayDeliveryQueue()
    queue.reconcile([refused, later])

    XCTAssertEqual(queue.next(now: now), refused)
    XCTAssertTrue(queue.refuse(requestID: "refused", now: now))
    XCTAssertEqual(queue.next(now: now), later)
    XCTAssertTrue(queue.confirm(requestID: "later") { _ in true })
    XCTAssertNil(queue.next(now: now), "the refused deposit waits out its backoff")
    XCTAssertEqual(queue.next(now: now + .seconds(1)), refused)
    XCTAssertTrue(queue.refuse(requestID: "refused", now: now + .seconds(1)))
    XCTAssertNil(queue.next(now: now + .seconds(2)), "a second refusal doubles the backoff")
    XCTAssertEqual(queue.next(now: now + .seconds(3)), refused)
    XCTAssertFalse(queue.refuse(requestID: "unknown", now: now))
  }

  func testReceiptWithoutRequestIDIsOnlyAcceptedForASingleDeposit() {
    let now = ContinuousClock.now
    var queue = PairwiseRelayDeliveryQueue()
    queue.reconcile([effect("a"), effect("b")])
    _ = queue.next(now: now)
    _ = queue.next(now: now)
    XCTAssertFalse(queue.confirm(requestID: nil) { _ in true })
    XCTAssertTrue(queue.confirm(requestID: "a") { _ in true })
    XCTAssertTrue(queue.confirm(requestID: nil) { $0 == "b" })
  }

  func testReconcileDropsItemsTheCoreNoLongerOwns() {
    let now = ContinuousClock.now
    var queue = PairwiseRelayDeliveryQueue()
    queue.reconcile([effect("a"), effect("b")])
    _ = queue.next(now: now)
    XCTAssertNotNil(queue.oldestInFlight)
    queue.reconcile([effect("b")])
    XCTAssertNil(queue.oldestInFlight)
    XCTAssertEqual(queue.next(now: now), effect("b"))
  }

  private func effect(_ id: String) -> PairwiseRelayEffect {
    PairwiseRelayEffect(id: id, recipient: Data(repeating: 1, count: 32), payload: Data([2]))
  }
}
