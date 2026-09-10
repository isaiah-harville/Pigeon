import Foundation

extension PigeonSendDirectApplication {
  func proto() throws -> Pigeon_Wire_V1_SendDirectApplication {
    var body = Pigeon_Wire_V1_SendDirectApplication()
    body.recipientIdentity = recipientIdentity
    body.application = try application.proto()
    return body
  }
}

extension PigeonDirectApplication {
  func proto() throws -> Pigeon_Wire_V1_DirectApplication {
    var application = Pigeon_Wire_V1_DirectApplication()
    application.applicationID = id
    switch body {
    case .message(let value):
      var message = Pigeon_Wire_V1_DirectMessage()
      message.text = value.text
      message.replySnippet = value.replySnippet ?? ""
      message.senderTimestampMs = value.senderTimestampMilliseconds
      application.message = message
    case .acknowledgement(let messageID):
      var acknowledgement = Pigeon_Wire_V1_DirectAcknowledgement()
      acknowledgement.messageID = messageID
      application.acknowledgement = acknowledgement
    case .reaction(let messageID, let emoji):
      var reaction = Pigeon_Wire_V1_DirectReaction()
      reaction.messageID = messageID
      if let emoji { reaction.emoji = emoji }
      application.reaction = reaction
    case .ephemeralState(let enabled):
      var state = Pigeon_Wire_V1_DirectEphemeralState()
      state.enabled = enabled
      application.ephemeralState = state
    case .transportState(let mode):
      var state = Pigeon_Wire_V1_DirectTransportState()
      state.mode = try mode.proto()
      application.transportState = state
    case .screenshotNotice:
      application.screenshotNotice = Pigeon_Wire_V1_DirectScreenshotNotice()
    case .contactAcceptance:
      application.contactAcceptance = Pigeon_Wire_V1_DirectContactAcceptance()
    case .relayRecommendation(let urls):
      var recommendation = Pigeon_Wire_V1_DirectRelayRecommendation()
      recommendation.relayUrls = urls
      application.relayRecommendation = recommendation
    }
    return application
  }

  init(proto: Pigeon_Wire_V1_DirectApplication) throws {
    id = proto.applicationID
    switch proto.body {
    case .message(let value):
      body = .message(
        PigeonDirectMessage(
          text: value.text, senderTimestampMilliseconds: value.senderTimestampMs,
          replySnippet: value.replySnippet.nilIfEmpty))
    case .acknowledgement(let value):
      body = .acknowledgement(messageID: value.messageID)
    case .reaction(let value):
      body = .reaction(messageID: value.messageID, emoji: value.hasEmoji ? value.emoji : nil)
    case .ephemeralState(let value):
      body = .ephemeralState(enabled: value.enabled)
    case .transportState(let value):
      body = .transportState(PigeonDirectTransportMode(proto: value.mode))
    case .screenshotNotice:
      body = .screenshotNotice
    case .contactAcceptance:
      body = .contactAcceptance
    case .relayRecommendation(let value):
      body = .relayRecommendation(urls: value.relayUrls)
    case nil:
      throw PigeonCoreWireError.missingEventBody
    }
  }
}

extension PigeonDirectTransportMode {
  init(proto: Pigeon_Wire_V1_DirectTransportMode) {
    switch proto {
    case .relay: self = .relay
    case .local: self = .local
    case .unspecified: self = .unknown(0)
    case .UNRECOGNIZED(let raw): self = .unknown(raw)
    }
  }

  func proto() throws -> Pigeon_Wire_V1_DirectTransportMode {
    switch self {
    case .relay: return .relay
    case .local: return .local
    case .unknown(let raw): throw PigeonCoreWireError.invalidDirectTransportMode(raw)
    }
  }
}

extension String {
  var nilIfEmpty: String? { isEmpty ? nil : self }
}
