//
//  MessageCodecTests.swift
//  PigeonTests
//
//  App-message and reaction wire codecs. These parse bytes that come out of the
//  ratchet, i.e. attacker-influencable input, so the decoders must clamp hostile
//  values and reject malformed ones rather than trusting them.
//

import XCTest

@testable import Pigeon

@MainActor
final class MessageCodecTests: XCTestCase {

  // MARK: - App messages

  func testMessageRoundTrips() throws {
    var message = ChatMessage(mine: true, text: "hello there")
    message.replySnippet = "earlier line"
    let encoded = try XCTUnwrap(SessionManager.encodeMessage(message))

    let decoded = try XCTUnwrap(SessionManager.decodeMessage(encoded))
    XCTAssertEqual(decoded.id, message.id)
    XCTAssertEqual(decoded.text, "hello there")
    XCTAssertEqual(decoded.replySnippet, "earlier line")
    // The decoded message is always an incoming one.
    XCTAssertFalse(decoded.mine)
  }

  func testMessageWithoutReplyDecodesNilSnippet() throws {
    let message = ChatMessage(mine: true, text: "no reply")
    let encoded = try XCTUnwrap(SessionManager.encodeMessage(message))
    let decoded = try XCTUnwrap(SessionManager.decodeMessage(encoded))
    XCTAssertNil(decoded.replySnippet)
  }

  func testDecodeMessageRejectsGarbage() {
    XCTAssertNil(SessionManager.decodeMessage(Data("not json".utf8)))
    XCTAssertNil(SessionManager.decodeMessage(Data()))
  }

  func testInboundReplySnippetIsClampedAndSingleLine() throws {
    // A hostile peer can put anything in the snippet; the sender-side preview
    // truncation is not trusted, so decode must clamp length and strip newlines.
    var message = ChatMessage(mine: true, text: "body")
    message.replySnippet = "line one\nline two " + String(repeating: "x", count: 200)
    let encoded = try XCTUnwrap(SessionManager.encodeMessage(message))

    let decoded = try XCTUnwrap(SessionManager.decodeMessage(encoded))
    let snippet = try XCTUnwrap(decoded.replySnippet)
    XCTAssertLessThanOrEqual(snippet.count, 80)
    XCTAssertFalse(snippet.contains("\n"))
  }

  // MARK: - Reactions

  func testReactionRoundTrips() throws {
    let id = UUID()
    let encoded = SessionManager.encodeReaction(messageID: id, emoji: "👍")
    let decoded = try XCTUnwrap(SessionManager.decodeReaction(encoded))
    XCTAssertEqual(decoded.messageID, id)
    XCTAssertEqual(decoded.emoji, "👍")
  }

  func testReactionRemovalDecodesNilEmoji() throws {
    let id = UUID()
    let encoded = SessionManager.encodeReaction(messageID: id, emoji: nil)
    let decoded = try XCTUnwrap(SessionManager.decodeReaction(encoded))
    XCTAssertEqual(decoded.messageID, id)
    XCTAssertNil(decoded.emoji)
  }

  func testInboundReactionIsClamped() throws {
    // A reaction should be one emoji; a long string must not slip through.
    let id = UUID()
    let encoded = SessionManager.encodeReaction(
      messageID: id, emoji: String(repeating: "🎉", count: 50))
    let decoded = try XCTUnwrap(SessionManager.decodeReaction(encoded))
    let emoji = try XCTUnwrap(decoded.emoji)
    XCTAssertLessThanOrEqual(emoji.count, 8)
  }

  func testDecodeReactionRejectsMalformed() {
    // Wrong command byte.
    XCTAssertNil(SessionManager.decodeReaction(Data([0x01]) + Data(UUID().uuidString.utf8)))
    // Too short to hold a UUID.
    XCTAssertNil(SessionManager.decodeReaction(Data([0x03, 0x00, 0x01])))
    // Non-UUID id bytes.
    XCTAssertNil(
      SessionManager.decodeReaction(Data([0x03]) + Data(String(repeating: "z", count: 36).utf8)))
  }

  // MARK: - Screenshot events

  func testScreenshotEventRoundTripsAsDurableSystemMessage() throws {
    var message = ChatMessage(mine: true, text: "You reported a screenshot", pending: true)
    message.system = true
    message.event = .screenshot

    let encoded = try XCTUnwrap(SessionManager.encodeMessage(message))
    let decoded = try XCTUnwrap(SessionManager.decodeMessage(encoded))

    XCTAssertTrue(decoded.system)
    XCTAssertEqual(decoded.event, .screenshot)
  }

  func testScreenshotNoticesIdentifyWhoCapturedTheChat() {
    XCTAssertEqual(
      SessionManager.screenshotNotice(mine: true, contactName: "Sam"),
      "You reported a screenshot")
    XCTAssertEqual(
      SessionManager.screenshotNotice(mine: false, contactName: "Sam"),
      "Sam reported a screenshot")
  }

  func testRelayRecommendationRoundTripsAsAuthenticatedTypedMessage() throws {
    var message = ChatMessage(mine: true, text: "Shared a relay", pending: true)
    message.system = true
    message.event = .relayRecommendation
    message.relayRecommendationURLs = ["wss://relay.example/ws"]

    let encoded = try XCTUnwrap(SessionManager.encodeMessage(message))
    let decoded = try XCTUnwrap(SessionManager.decodeMessage(encoded))

    XCTAssertEqual(decoded.event, .relayRecommendation)
    XCTAssertEqual(decoded.relayRecommendationURLs, ["wss://relay.example/ws"])
  }

  func testRelayRecommendationDropsUnsafeAndOversizedEndpoints() throws {
    var message = ChatMessage(mine: true, text: "Shared a relay", pending: true)
    message.system = true
    message.event = .relayRecommendation
    message.relayRecommendationURLs =
      [
        "https://not-a-websocket.example",
        "wss://user:password@relay.example/ws",
      ]
      + (0...RelaySettings.maximumSharedRelayCount).map { index in
        "wss://relay\(index).example/ws"
      }

    let encoded = try XCTUnwrap(SessionManager.encodeMessage(message))
    let decoded = try XCTUnwrap(SessionManager.decodeMessage(encoded))

    XCTAssertEqual(decoded.relayRecommendationURLs, [])
  }
}
