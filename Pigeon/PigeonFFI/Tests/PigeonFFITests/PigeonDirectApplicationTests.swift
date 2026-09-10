import Foundation
import XCTest

@testable import PigeonFFI

final class PigeonDirectApplicationTests: XCTestCase {
  func testTypedBodiesRoundTripThroughProtobuf() throws {
    let bodies: [PigeonDirectApplication.Body] = [
      .message(PigeonDirectMessage(text: "hello", senderTimestampMilliseconds: 1)),
      .acknowledgement(messageID: "message"),
      .reaction(messageID: "message", emoji: "🕊️"),
      .reaction(messageID: "message", emoji: nil),
      .ephemeralState(enabled: true),
      .transportState(.local),
      .screenshotNotice,
      .contactAcceptance,
      .relayRecommendation(urls: ["https://relay.example"]),
    ]

    for (index, body) in bodies.enumerated() {
      let application = PigeonDirectApplication(id: "application-\(index)", body: body)
      let command = PigeonCoreCommand(
        id: "command-\(index)",
        body: .sendDirectApplication(
          PigeonSendDirectApplication(
            recipientIdentity: Data(repeating: 7, count: 32), application: application)))

      let proto = try command.proto()

      XCTAssertEqual(proto.sendDirectApplication.recipientIdentity, Data(repeating: 7, count: 32))
      XCTAssertEqual(
        try PigeonDirectApplication(proto: proto.sendDirectApplication.application),
        application)
    }
  }

  func testReceivedApplicationMapsToTransportNeutralEvent() throws {
    var message = Pigeon_Wire_V1_DirectMessage()
    message.text = "hello directly"
    message.replySnippet = "parent"
    message.senderTimestampMs = 1_234
    var application = Pigeon_Wire_V1_DirectApplication()
    application.applicationID = "direct-message"
    application.message = message
    var received = Pigeon_Wire_V1_DirectApplicationReceived()
    received.senderIdentity = Data(repeating: 9, count: 32)
    received.application = application
    var event = Pigeon_Wire_V1_AppEvent()
    event.version = 1
    event.eventID = "direct"
    event.directApplicationReceived = received

    XCTAssertEqual(
      try PigeonCoreEvent(proto: event).body,
      .directApplicationReceived(
        PigeonDirectApplicationReceivedEvent(
          senderIdentity: Data(repeating: 9, count: 32),
          application: PigeonDirectApplication(
            id: "direct-message",
            body: .message(
              PigeonDirectMessage(
                text: "hello directly", senderTimestampMilliseconds: 1_234,
                replySnippet: "parent"))))))
  }
}
