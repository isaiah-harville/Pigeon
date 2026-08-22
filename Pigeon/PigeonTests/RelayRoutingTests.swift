//
//  RelayRoutingTests.swift
//  PigeonTests
//
//  Pure routing/decision logic of the relay client: addressed per-recipient
//  delivery, federation relay selection, the connection-set union, and
//  robustness to malformed server frames.
//

import XCTest

@testable import Pigeon

@MainActor
final class RelayRoutingTests: XCTestCase {

  private func url(_ s: String) -> URL { URL(string: s)! }

  func testCompatibilitySelectsHighestOverlappingVersion() {
    XCTAssertEqual(RelayTransport.selectProtocol(serverMinimum: 1, serverMaximum: 3), 1)
  }

  func testCompatibilityRejectsDisjointOrInvalidRanges() {
    XCTAssertNil(RelayTransport.selectProtocol(serverMinimum: 2, serverMaximum: 3))
    XCTAssertNil(RelayTransport.selectProtocol(serverMinimum: 1, serverMaximum: 0))
  }

  func testRelayInfoParsesCompatibleVersionMetadata() {
    let info = RelayTransport.relayInfo(from: [
      "type": "compatible",
      "protocol_version": 1,
      "relay_version": "0.2.0",
      "min_protocol_version": 1,
      "max_protocol_version": 2,
    ])

    XCTAssertEqual(
      info,
      .init(
        relayVersion: "0.2.0", minimumProtocolVersion: 1, maximumProtocolVersion: 2,
        selectedProtocolVersion: 1, compatibility: .compatible))
  }

  func testRelayInfoDirectsUpdateTowardOlderSide() {
    XCTAssertEqual(
      RelayTransport.relayInfo(from: [
        "type": "incompatible", "relay_version": "0.1.0",
        "min_protocol_version": 0, "max_protocol_version": 0,
      ])?.compatibility,
      .updateRelay)
    XCTAssertEqual(
      RelayTransport.relayInfo(from: [
        "type": "incompatible", "relay_version": "0.3.0",
        "min_protocol_version": 2, "max_protocol_version": 3,
      ])?.compatibility,
      .updateApp)
  }

  func testRelayInfoRejectsBooleanAndFractionalProtocolVersions() {
    XCTAssertNil(
      RelayTransport.relayInfo(from: [
        "type": "compatible", "protocol_version": true,
      ]))
    XCTAssertNil(
      RelayTransport.relayInfo(from: [
        "type": "incompatible", "min_protocol_version": 1.5,
        "max_protocol_version": 2,
      ]))
    XCTAssertNil(
      RelayTransport.relayInfo(from: [
        "type": "incompatible", "min_protocol_version": 1,
        "max_protocol_version": false,
      ]))
  }

  func testRelayProbeTimeoutCancelsAStalledOperation() async {
    let clock = ContinuousClock()
    let started = clock.now
    do {
      let _: String = try await RelayPinger.withTimeout(.milliseconds(20)) {
        try await Task.sleep(for: .seconds(10))
        return "late"
      }
      XCTFail("A silent relay must time out")
    } catch RelayError.timeout {
      XCTAssertLessThan(started.duration(to: clock.now), .seconds(1))
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  func testOlderCompatibleRelayWithoutReleaseMetadataRemainsUsable() {
    XCTAssertEqual(
      RelayTransport.relayInfo(from: ["type": "compatible", "protocol_version": 1]),
      .init(
        relayVersion: nil, minimumProtocolVersion: nil, maximumProtocolVersion: nil,
        selectedProtocolVersion: 1, compatibility: .compatible))
  }

  func testAnonymousProbeUsesTextHelloFrameAcceptedByRelay() throws {
    switch try RelayTransport.helloMessage() {
    case .string(let text):
      let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
      XCTAssertEqual(object["type"] as? String, "hello")
      XCTAssertEqual(object["min_protocol_version"] as? Int, 1)
      XCTAssertEqual(object["max_protocol_version"] as? Int, 1)
    case .data:
      XCTFail("The relay ignores binary WebSocket frames")
    @unknown default:
      XCTFail("Unsupported WebSocket message type")
    }
  }

  func testIncompatibleRelaysAreNotAdvertised() {
    let compatible = url("wss://compatible.example/ws")
    let incompatible = url("wss://old.example/ws")
    XCTAssertEqual(
      RelayTransport.advertisedRelays(
        configured: [compatible, incompatible], excluding: [incompatible]),
      [compatible])
  }

  func testReconfigureRetainsKnownIncompatibilityUntilRelayNegotiatesSuccessfully() {
    let incompatible = url("wss://old.example/ws")
    XCTAssertEqual(
      RelayTransport.retainedIncompatibleRelays(
        current: [incompatible], wanted: [incompatible]),
      [incompatible])
  }

  // MARK: - Addressed delivery + federation selection

  func testDeliveryPrefersRecipientAdvertisedRelays() {
    let advertised = [url("wss://theirs.example/ws")]
    // Federation: deposit only on the recipient's relays.
    XCTAssertEqual(RelayTransport.deliveryTargets(advertised: advertised), advertised)
  }

  func testDeliveryTargetsNothingWhenRecipientAdvertisesNone() {
    // No own-relay fallback: a contact who advertises no relay can't be reached
    // over the internet (they don't read our mailbox relays), so we target
    // nothing rather than depositing somewhere undeliverable.
    XCTAssertTrue(RelayTransport.deliveryTargets(advertised: []).isEmpty)
  }

  // MARK: - Per-conversation preferred relay

  func testPreferredRelayIsOrderedFirstWithOthersAsFallback() {
    let a = url("wss://a.example/ws")
    let b = url("wss://b.example/ws")
    let c = url("wss://c.example/ws")
    // Preferred relay leads; the rest follow in order so a dead preferred
    // falls through to them.
    XCTAssertEqual(
      RelayTransport.deliveryTargets(preferred: b, advertised: [a, b, c]),
      [b, a, c])
  }

  func testPreferredNotAdvertisedIsIgnored() {
    let a = url("wss://a.example/ws")
    let stray = url("wss://stray.example/ws")
    // A preference the recipient doesn't advertise can't be honored — fall back
    // to their advertised relays unchanged.
    XCTAssertEqual(RelayTransport.deliveryTargets(preferred: stray, advertised: [a]), [a])
  }

  func testPreferredIgnoredWhenAdvertisesNoneTargetsNothing() {
    let stray = url("wss://stray.example/ws")
    XCTAssertTrue(RelayTransport.deliveryTargets(preferred: stray, advertised: []).isEmpty)
  }

  func testNilPreferredMatchesPlainDelivery() {
    let a = url("wss://a.example/ws")
    let b = url("wss://b.example/ws")
    XCTAssertEqual(RelayTransport.deliveryTargets(preferred: nil, advertised: [a, b]), [a, b])
  }

  // MARK: - Connection set (reconfigure union)

  func testWantedConnectionsUnionsAndDeduplicatesPreservingOrder() {
    let mine = [url("wss://a.example/ws"), url("wss://b.example/ws")]
    let contacts = [url("wss://b.example/ws"), url("wss://c.example/ws")]
    XCTAssertEqual(
      RelayTransport.wantedConnections(myRelays: mine, contactRelays: contacts),
      [url("wss://a.example/ws"), url("wss://b.example/ws"), url("wss://c.example/ws")])
  }

  func testWantedConnectionsEmptyWhenNothingConfigured() {
    XCTAssertTrue(RelayTransport.wantedConnections(myRelays: [], contactRelays: []).isEmpty)
  }

  // MARK: - Malformed / failure-path response handling

  func testClassifyValidEnvelope() {
    let ciphertext = Data([1, 2, 3, 4])
    let frame = RelayTransport.classifyInbound([
      "type": "envelope", "id": "abc", "ciphertext": ciphertext.base64EncodedString(),
    ])
    XCTAssertEqual(frame, .envelope(.init(id: "abc", ciphertext: ciphertext)))
  }

  func testClassifyEnvelopeMissingFieldsIsIgnored() {
    XCTAssertEqual(RelayTransport.classifyInbound(["type": "envelope", "id": "abc"]), .ignored)
    XCTAssertEqual(
      RelayTransport.classifyInbound(["type": "envelope", "ciphertext": "AQID"]), .ignored)
  }

  func testClassifyEnvelopeWithNonBase64CiphertextIsIgnored() {
    let frame = RelayTransport.classifyInbound([
      "type": "envelope", "id": "abc", "ciphertext": "not base64!!",
    ])
    XCTAssertEqual(frame, .ignored)
  }

  func testClassifyErrorAndUnknownTypes() {
    XCTAssertEqual(
      RelayTransport.classifyInbound(["type": "error", "message": "boom"]), .error("boom"))
    XCTAssertEqual(RelayTransport.classifyInbound(["type": "error"]), .error("error"))
    XCTAssertEqual(RelayTransport.classifyInbound(["type": "wat"]), .ignored)
    XCTAssertEqual(RelayTransport.classifyInbound([:]), .ignored)
  }

  // MARK: - Mailbox acknowledgement gating

  func testRelayAcknowledgesOnlyDurablyConsumedMessages() {
    XCTAssertTrue(RelayTransport.shouldAcknowledge(.consumed))
    XCTAssertFalse(RelayTransport.shouldAcknowledge(.retryAfterRestart))
  }

  // MARK: - Send-side store-and-forward queue

  private func deposit(_ to: UInt8, _ body: UInt8) -> RelayTransport.DepositQueue.Deposit {
    .init(recipient: Data([to]), message: Data([body]))
  }

  func testFlushRedeliversQueuedDepositWhenRelayBecomesReady() {
    // Reproduces the ack-drop wedge: a deposit (e.g. a delivery ack) made while
    // no relay link was ready must go out the instant one comes up, not vanish.
    var queue = RelayTransport.DepositQueue(bound: 8)
    queue.enqueue(deposit(1, 42))
    XCTAssertEqual(queue.count, 1)

    var sent: [RelayTransport.DepositQueue.Deposit] = []
    queue.flush {
      sent.append($0)
      return true
    }  // a relay is ready now
    XCTAssertEqual(sent, [deposit(1, 42)])
    XCTAssertTrue(queue.isEmpty, "a delivered deposit must not be retained")
  }

  func testFlushRetainsDepositsThatStillFindNoReadyRelay() {
    var queue = RelayTransport.DepositQueue(bound: 8)
    queue.enqueue(deposit(1, 1))
    queue.enqueue(deposit(2, 2))
    queue.flush { _ in false }  // still nothing ready
    XCTAssertEqual(queue.deposits, [deposit(1, 1), deposit(2, 2)])
  }

  func testFlushKeepsOnlyTheUndeliverableDeposits() {
    var queue = RelayTransport.DepositQueue(bound: 8)
    queue.enqueue(deposit(1, 1))  // reachable
    queue.enqueue(deposit(2, 2))  // unreachable
    queue.flush { $0.recipient == Data([1]) }
    XCTAssertEqual(queue.deposits, [deposit(2, 2)])
  }

  func testQueueDropsOldestPastItsBound() {
    var queue = RelayTransport.DepositQueue(bound: 2)
    queue.enqueue(deposit(1, 1))
    queue.enqueue(deposit(2, 2))
    queue.enqueue(deposit(3, 3))  // evicts the oldest
    XCTAssertEqual(queue.deposits, [deposit(2, 2), deposit(3, 3)])
  }
}
