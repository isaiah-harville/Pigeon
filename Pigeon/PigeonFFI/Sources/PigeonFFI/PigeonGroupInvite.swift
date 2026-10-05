import Foundation

public enum PigeonGroupInviteMode: Equatable, Sendable {
  case unspecified
  case `public`
  case `private`
}

public enum PigeonGroupInviteProgress: Equatable, Sendable {
  case unspecified
  case pending
  case approved
  case rejected
  case expired
  case full
  case joined
}

public enum PigeonGroupInviteEnvelopeOutcome: Equatable, Sendable {
  case unspecified
  case accepted
  case rejected
}

public struct PigeonCreateGroupInvite: Equatable, Sendable {
  public let groupID: Data
  public let mode: PigeonGroupInviteMode
  public let expiresAtMilliseconds: Int64
  public let nowMilliseconds: Int64

  public init(
    groupID: Data, mode: PigeonGroupInviteMode,
    expiresAtMilliseconds: Int64, nowMilliseconds: Int64
  ) {
    self.groupID = groupID
    self.mode = mode
    self.expiresAtMilliseconds = expiresAtMilliseconds
    self.nowMilliseconds = nowMilliseconds
  }

  public init(
    groupID: Data, publicMode: Bool,
    expiresAtMilliseconds: Int64, nowMilliseconds: Int64
  ) {
    self.init(
      groupID: groupID, mode: publicMode ? .public : .private,
      expiresAtMilliseconds: expiresAtMilliseconds,
      nowMilliseconds: nowMilliseconds)
  }
}

public struct PigeonRevokeGroupInvite: Equatable, Sendable {
  public let inboxAddress: Data

  public init(inboxAddress: Data) { self.inboxAddress = inboxAddress }
}

public struct PigeonStartGroupInviteJoin: Equatable, Sendable {
  public let ticket: Data
  public let nowMilliseconds: Int64

  public init(ticket: Data, nowMilliseconds: Int64) {
    self.ticket = ticket
    self.nowMilliseconds = nowMilliseconds
  }
}

public struct PigeonApplyGroupInviteInboxEnvelope: Equatable, Sendable {
  public let inboxAddress: Data
  public let ciphertext: Data
  public let nowMilliseconds: Int64

  public init(inboxAddress: Data, ciphertext: Data, nowMilliseconds: Int64) {
    self.inboxAddress = inboxAddress
    self.ciphertext = ciphertext
    self.nowMilliseconds = nowMilliseconds
  }
}

public struct PigeonDecideGroupInviteRequest: Equatable, Sendable {
  public let inboxAddress: Data
  public let requestID: Data
  public let approve: Bool
  public let nowMilliseconds: Int64

  public init(
    inboxAddress: Data, requestID: Data, approve: Bool, nowMilliseconds: Int64
  ) {
    self.inboxAddress = inboxAddress
    self.requestID = requestID
    self.approve = approve
    self.nowMilliseconds = nowMilliseconds
  }
}

public struct PigeonApplyGroupInviteReply: Equatable, Sendable {
  public let replyAddress: Data
  public let ciphertext: Data
  public let nowMilliseconds: Int64

  public init(replyAddress: Data, ciphertext: Data, nowMilliseconds: Int64) {
    self.replyAddress = replyAddress
    self.ciphertext = ciphertext
    self.nowMilliseconds = nowMilliseconds
  }
}

public struct PigeonRefreshGroupInvites: Equatable, Sendable {
  public let nowMilliseconds: Int64

  public init(nowMilliseconds: Int64) { self.nowMilliseconds = nowMilliseconds }
}

public struct PigeonGroupInviteRequestState: Equatable, Sendable {
  public let requestID: Data
  public let requesterIdentity: Data
  public let progress: PigeonGroupInviteProgress
}

public struct PigeonGroupInviteState: Equatable, Sendable {
  public let ticket: Data
  public let requests: [PigeonGroupInviteRequestState]
}

public struct PigeonGroupInviteJoinState: Equatable, Sendable {
  public let ticket: Data
  public let requestID: Data
  public let replyAddress: Data
  public let progress: PigeonGroupInviteProgress
}

extension PigeonGroupInviteMode {
  func proto() -> Pigeon_Wire_V1_GroupInviteMode {
    switch self {
    case .unspecified: .unspecified
    case .public: .public
    case .private: .private
    }
  }
}

extension PigeonGroupInviteProgress {
  init(proto: Pigeon_Wire_V1_GroupInviteProgress) {
    switch proto {
    case .unspecified: self = .unspecified
    case .pending: self = .pending
    case .approved: self = .approved
    case .rejected: self = .rejected
    case .expired: self = .expired
    case .full: self = .full
    case .joined: self = .joined
    case .UNRECOGNIZED: self = .unspecified
    }
  }
}

extension PigeonCreateGroupInvite {
  func proto() -> Pigeon_Wire_V1_CreateGroupInvite {
    var value = Pigeon_Wire_V1_CreateGroupInvite()
    value.groupID = groupID
    value.mode = mode.proto()
    value.expiresAtMs = expiresAtMilliseconds
    value.nowMs = nowMilliseconds
    return value
  }
}

extension PigeonRevokeGroupInvite {
  func proto() -> Pigeon_Wire_V1_RevokeGroupInvite {
    var value = Pigeon_Wire_V1_RevokeGroupInvite()
    value.inboxAddress = inboxAddress
    return value
  }
}

extension PigeonStartGroupInviteJoin {
  func proto() -> Pigeon_Wire_V1_StartGroupInviteJoin {
    var value = Pigeon_Wire_V1_StartGroupInviteJoin()
    value.ticket = ticket
    value.nowMs = nowMilliseconds
    return value
  }
}

extension PigeonApplyGroupInviteInboxEnvelope {
  func proto() -> Pigeon_Wire_V1_ApplyGroupInviteInboxEnvelope {
    var value = Pigeon_Wire_V1_ApplyGroupInviteInboxEnvelope()
    value.inboxAddress = inboxAddress
    value.ciphertext = ciphertext
    value.nowMs = nowMilliseconds
    return value
  }
}

extension PigeonDecideGroupInviteRequest {
  func proto() -> Pigeon_Wire_V1_DecideGroupInviteRequest {
    var value = Pigeon_Wire_V1_DecideGroupInviteRequest()
    value.inboxAddress = inboxAddress
    value.requestID = requestID
    value.approve = approve
    value.nowMs = nowMilliseconds
    return value
  }
}

extension PigeonApplyGroupInviteReply {
  func proto() -> Pigeon_Wire_V1_ApplyGroupInviteReply {
    var value = Pigeon_Wire_V1_ApplyGroupInviteReply()
    value.replyAddress = replyAddress
    value.ciphertext = ciphertext
    value.nowMs = nowMilliseconds
    return value
  }
}

extension PigeonRefreshGroupInvites {
  func proto() -> Pigeon_Wire_V1_RefreshGroupInvites {
    var value = Pigeon_Wire_V1_RefreshGroupInvites()
    value.nowMs = nowMilliseconds
    return value
  }
}

extension PigeonGroupInviteState {
  init(proto: Pigeon_Wire_V1_GroupInviteState) {
    ticket = proto.ticket
    requests = proto.requests.map { request in
      PigeonGroupInviteRequestState(
        requestID: request.requestID,
        requesterIdentity: request.requesterIdentity,
        progress: PigeonGroupInviteProgress(proto: request.progress))
    }
  }
}

extension PigeonGroupInviteJoinState {
  init(proto: Pigeon_Wire_V1_GroupInviteJoinState) {
    ticket = proto.ticket
    requestID = proto.requestID
    replyAddress = proto.replyAddress
    progress = PigeonGroupInviteProgress(proto: proto.progress)
  }
}
