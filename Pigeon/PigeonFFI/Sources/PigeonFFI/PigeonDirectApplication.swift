import Foundation

public struct PigeonSendDirectApplication: Equatable, Sendable {
  public let recipientIdentity: Data
  public let application: PigeonDirectApplication
  public let localOnly: Bool

  public init(
    recipientIdentity: Data, application: PigeonDirectApplication,
    localOnly: Bool = false
  ) {
    self.recipientIdentity = recipientIdentity
    self.application = application
    self.localOnly = localOnly
  }
}

public struct PigeonDirectApplication: Equatable, Sendable {
  public enum Body: Equatable, Sendable {
    case message(PigeonDirectMessage)
    case acknowledgement(messageID: String)
    case reaction(messageID: String, emoji: String?)
    case ephemeralState(enabled: Bool)
    case transportState(PigeonDirectTransportMode)
    case screenshotNotice
    case contactAcceptance
    case relayRecommendation(urls: [String])
  }

  public let id: String
  public let body: Body

  public init(id: String, body: Body) {
    self.id = id
    self.body = body
  }
}

public struct PigeonDirectMessage: Equatable, Sendable {
  public let text: String
  public let replySnippet: String?
  public let senderTimestampMilliseconds: Int64

  public init(
    text: String, senderTimestampMilliseconds: Int64,
    replySnippet: String? = nil
  ) {
    self.text = text
    self.replySnippet = replySnippet
    self.senderTimestampMilliseconds = senderTimestampMilliseconds
  }
}

public enum PigeonDirectTransportMode: Equatable, Sendable {
  case relay
  case local
  case unknown(Int)
}

public struct PigeonDirectApplicationReceivedEvent: Equatable, Sendable {
  public let senderIdentity: Data
  public let application: PigeonDirectApplication

  public init(senderIdentity: Data, application: PigeonDirectApplication) {
    self.senderIdentity = senderIdentity
    self.application = application
  }
}
