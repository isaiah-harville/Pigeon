import Foundation

extension PigeonCoreCommand {
  func proto() throws -> Pigeon_Wire_V1_ClientCommand {
    var command = Pigeon_Wire_V1_ClientCommand()
    command.version = 1
    command.commandID = id
    if try encodeGroupBody(into: &command) {
      return command
    }
    guard try encodePairwiseBody(into: &command) else {
      throw PigeonCoreWireError.invalidCommandBody
    }
    return command
  }

  private func encodeGroupBody(into command: inout Pigeon_Wire_V1_ClientCommand) throws -> Bool {
    switch body {
    case .createGroup(let value):
      command.createGroup = value.proto()
    case .sendGroupMessage(let value):
      command.sendGroupMessage = value.proto()
    case .applyInbound(let value):
      command.applyInbound = try value.proto()
    case .changeGroupPolicy(let value):
      command.changeGroupPolicy = try value.proto()
    case .acknowledgeEffects(let value):
      command.acknowledgeEffects = value.proto()
    case .confirmGroupRelayAuthorization(let value):
      var confirmation = Pigeon_Wire_V1_ConfirmGroupRelayAuthorization()
      confirmation.groupID = value.groupID
      confirmation.capabilityID = value.capabilityID
      command.confirmGroupRelayAuthorization = confirmation
    case .recoverGroup(let value):
      var recovery = Pigeon_Wire_V1_RecoverGroup()
      recovery.recoveryCertificate = value.recoveryCertificate
      command.recoverGroup = recovery
    case .beginGroupRecovery(let value):
      var recovery = Pigeon_Wire_V1_BeginGroupRecovery()
      recovery.groupID = value.groupID
      recovery.replacementRelayURL = value.replacementRelayURL
      recovery.replacementCoordinationID = value.replacementCoordinationID
      recovery.replacementCoordinatorPublicKey = value.replacementCoordinatorPublicKey
      command.beginGroupRecovery = recovery
    default:
      return false
    }
    return true
  }

  private func encodePairwiseBody(into command: inout Pigeon_Wire_V1_ClientCommand) throws -> Bool {
    switch body {
    case .ensurePairwiseAccount:
      command.ensurePairwiseAccount = Pigeon_Wire_V1_EnsurePairwiseAccount()
    case .registerPairwiseContact(let value):
      command.registerPairwiseContact = try value.proto()
    case .sendPairwiseControl(let value):
      command.sendPairwiseControl = try value.proto()
    case .sendDirectApplication(let value):
      command.sendDirectApplication = try value.proto()
    case .setPairwiseRelationship(let value):
      command.setPairwiseRelationship = try value.proto()
    case .removePairwiseContact(let identity):
      var body = Pigeon_Wire_V1_RemovePairwiseContact()
      body.identity = identity
      command.removePairwiseContact = body
    case .migrateLegacyPairwiseState(let value):
      command.migrateLegacyPairwiseState = value.proto()
    default:
      return false
    }
    return true
  }
}

extension PigeonLegacyPairwiseMigration {
  func proto() -> Pigeon_Wire_V1_MigrateLegacyPairwiseState {
    var migration = Pigeon_Wire_V1_MigrateLegacyPairwiseState()
    migration.formatVersion = 1
    migration.accountState = accountState
    migration.fallbackKey = fallbackKey
    migration.sessions = sessions.map { session in
      var encoded = Pigeon_Wire_V1_LegacyPairwiseSession()
      encoded.remoteIdentity = session.remoteIdentity
      encoded.state = session.state
      return encoded
    }
    return migration
  }
}

extension PigeonSendGroupMessage {
  func proto() -> Pigeon_Wire_V1_SendGroupMessage {
    var body = Pigeon_Wire_V1_SendGroupMessage()
    body.groupID = groupID
    body.messageID = messageID
    body.body = self.body
    body.replyToMessageID = replyToMessageID ?? ""
    body.senderTimestampMs = senderTimestampMilliseconds
    return body
  }
}

extension PigeonApplyInbound {
  func proto() throws -> Pigeon_Wire_V1_ApplyInbound {
    var body = Pigeon_Wire_V1_ApplyInbound()
    body.kind = try kind.proto()
    body.payload = payload
    body.requestID = requestID
    return body
  }
}

extension PigeonChangeGroupPolicy {
  func proto() throws -> Pigeon_Wire_V1_ChangeGroupPolicy {
    var body = Pigeon_Wire_V1_ChangeGroupPolicy()
    body.groupID = groupID
    body.kind = try kind.proto()
    body.subjectIdentity = subjectIdentity
    body.stringValue = stringValue
    body.boolValue = boolValue
    return body
  }
}
