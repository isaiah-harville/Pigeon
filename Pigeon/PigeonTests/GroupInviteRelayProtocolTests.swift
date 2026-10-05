import XCTest

@testable import Pigeon

@MainActor
final class GroupInviteRelayProtocolTests: XCTestCase {
  func testPublishUsesAnonymousMailboxAndOpaqueCiphertext() throws {
    let outbound = GroupInviteRelayTransport.Outbound(
      id: "01234567-89ab-cdef-0123-456789abcdef",
      relayURL: try XCTUnwrap(URL(string: "wss://relay.example/group")),
      destination: Data(repeating: 0x2a, count: 32),
      ciphertext: Data([0, 1, 2, 3]))
    let frame = try GroupInviteRelayProtocol.publish(outbound)
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: frame) as? [String: Any])
    XCTAssertEqual(object["type"] as? String, "invite_publish")
    XCTAssertEqual(object["recipient"] as? String, outbound.destination.hexEncoded)
    XCTAssertEqual(object["request_id"] as? String, outbound.id)
    XCTAssertEqual(object["ciphertext"] as? String, outbound.ciphertext.base64EncodedString())
    XCTAssertNil(object["sender"])
    XCTAssertNil(object["push_token"])
  }

  func testRejectsOversizeInboundAndNonTLSInviteEndpoints() throws {
    let oversize = Data(repeating: 0x20, count: GroupInviteRelayProtocol.maximumFrameBytes + 1)
    XCTAssertThrowsError(try GroupInviteRelayProtocol.decode(oversize))
    XCTAssertNil(
      GroupInviteRelayTransport.endpoint(
        for: try XCTUnwrap(URL(string: "file:///tmp/relay"))))
    XCTAssertNil(
      GroupInviteRelayTransport.endpoint(
        for: try XCTUnwrap(URL(string: "http://relay.example"))))
    XCTAssertNil(
      GroupInviteRelayTransport.endpoint(
        for: try XCTUnwrap(URL(string: "ws://relay.example"))))
  }

  func testReceiptDoesNotRemoveNextEffectAfterCoreReconfiguration() throws {
    let url = try XCTUnwrap(URL(string: "wss://relay.example"))
    let first = GroupInviteRelayTransport.Outbound(
      id: "01234567-89ab-cdef-0123-456789abcdef", relayURL: url,
      destination: Data(repeating: 1, count: 32), ciphertext: Data([1]))
    let next = GroupInviteRelayTransport.Outbound(
      id: "11234567-89ab-cdef-0123-456789abcdef", relayURL: url,
      destination: Data(repeating: 2, count: 32), ciphertext: Data([2]))
    XCTAssertEqual(
      GroupInviteRelayTransport.pendingAfterReceipt(
        [first, next], confirmedID: first.id), [next])
    XCTAssertEqual(
      GroupInviteRelayTransport.pendingAfterReceipt(
        [next], confirmedID: first.id), [next])
  }
}
