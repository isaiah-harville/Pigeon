import CryptoKit
import Foundation
import XCTest

@testable import PigeonFFI

final class PigeonCoreFacadeTests: XCTestCase {
  private final class Identity: PlatformIdentity, @unchecked Sendable {
    private let key = Curve25519.Signing.PrivateKey()

    func ensurePublicKey(purpose _: IdentityPurposeRequest) -> Data {
      key.publicKey.rawRepresentation
    }

    func sign(purpose _: IdentityPurposeRequest, message: Data) throws -> Data {
      try key.signature(for: message)
    }
  }

  private final class Store: CheckpointStore, @unchecked Sendable {
    private let lock = NSLock()
    private var checkpoint: Checkpoint?

    func load() -> Checkpoint? {
      lock.withLock { checkpoint }
    }

    func replace(expectedGeneration: UInt64, next: Checkpoint) throws {
      try lock.withLock {
        guard checkpoint?.generation ?? 0 == expectedGeneration else {
          throw PlatformError.Conflict
        }
        checkpoint = next
      }
    }
  }

  func testPublicFacadeCreatesGroupAndReturnsTypedOutboundActions() throws {
    let client = try PigeonCoreClient(identity: Identity(), store: Store())
    let command = PigeonCoreCommand(
      id: "public-create",
      body: .createGroup(
        PigeonCreateGroup(
          name: "Birds",
          memberIdentities: [Data(repeating: 8, count: 32), Data(repeating: 9, count: 32)],
          relayURL: "https://relay.example",
          meshEnabled: false,
          coordinatorPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)))

    let output = try client.execute(command)

    XCTAssertEqual(output.checkpointGeneration, 1)
    XCTAssertEqual(output.events, [])
    XCTAssertEqual(output.outbound.map(\.kind), [.groupJoinRequest, .groupJoinRequest])
    XCTAssertEqual(
      output.outbound.map(\.destination),
      [Data(repeating: 8, count: 32), Data(repeating: 9, count: 32)])
  }

  func testFacadeMapsEveryEventAndPreservesUnknownEnums() throws {
    var output = Pigeon_Wire_V1_ClientOutput()
    output.checkpointGeneration = 12
    output.events = eventFixtures()
    var outbound = Pigeon_Wire_V1_OutboundItem()
    outbound.itemID = "future"
    outbound.kind = .UNRECOGNIZED(73)
    output.outbound = [outbound]

    let mapped = try PigeonCoreOutput(proto: output)

    XCTAssertEqual(mapped.checkpointGeneration, 12)
    XCTAssertEqual(
      mapped.events.map(\.id),
      [
        "created", "message", "reaction", "policy", "delivery", "warning",
      ])
    assertEventBodies(mapped.events)
    XCTAssertEqual(mapped.outbound.map(\.kind), [.unknown(73)])
  }

  private func eventFixtures() -> [Pigeon_Wire_V1_AppEvent] {
    var created = Pigeon_Wire_V1_GroupCreated()
    created.groupID = Data([1])
    created.ownerIdentity = Data([2])
    created.name = "Birds"
    created.relayURL = "https://relay.example"
    created.meshEnabled = true
    created.epoch = 3
    created.policyRevision = 4

    var message = Pigeon_Wire_V1_GroupMessageReceived()
    message.groupID = Data([1])
    message.messageID = "message"
    message.senderIdentity = Data([3])
    message.body = Data("hello".utf8)
    message.replyToMessageID = "parent"
    message.epoch = 5

    var reaction = Pigeon_Wire_V1_GroupReactionReceived()
    reaction.groupID = Data([1])
    reaction.messageID = "reaction"
    reaction.senderIdentity = Data([4])
    reaction.targetMessageID = "message"
    reaction.reaction = "bird"
    reaction.epoch = 6

    return [
      event(id: "created", body: .groupCreated(created)),
      event(id: "message", body: .groupMessageReceived(message)),
      event(id: "reaction", body: .groupReactionReceived(reaction)),
      event(id: "policy", body: .groupPolicyChanged(policyFixture())),
      event(id: "delivery", body: .groupDeliveryChanged(deliveryFixture())),
      event(id: "warning", body: .groupSecurityWarning(warningFixture())),
    ]
  }

  private func policyFixture() -> Pigeon_Wire_V1_GroupPolicyChanged {
    var policy = Pigeon_Wire_V1_GroupPolicyChanged()
    policy.kind = .UNRECOGNIZED(71)
    policy.groupID = Data([1])
    policy.actorIdentity = Data([5])
    policy.subjectIdentity = Data([6])
    policy.epoch = 7
    policy.policyRevision = 8
    policy.name = "Flock"
    policy.relayURL = "https://relay-two.example"
    return policy
  }

  private func deliveryFixture() -> Pigeon_Wire_V1_GroupDeliveryChanged {
    var delivery = Pigeon_Wire_V1_GroupDeliveryChanged()
    delivery.groupID = Data([1])
    delivery.messageID = "message"
    delivery.state = .UNRECOGNIZED(72)
    delivery.epoch = 9
    delivery.deliveredCount = 2
    delivery.intendedCount = 3
    return delivery
  }

  private func warningFixture() -> Pigeon_Wire_V1_GroupSecurityWarning {
    var warning = Pigeon_Wire_V1_GroupSecurityWarning()
    warning.groupID = Data([1])
    warning.code = 10
    warning.evidenceID = Data([7])
    warning.epoch = 11
    return warning
  }

  private func assertEventBodies(_ events: [PigeonCoreEvent]) {
    XCTAssertEqual(
      events[0].body,
      .groupCreated(
        PigeonGroupCreatedEvent(
          groupID: Data([1]), ownerIdentity: Data([2]), name: "Birds",
          relayURL: "https://relay.example", meshEnabled: true, epoch: 3, policyRevision: 4)))
    XCTAssertEqual(
      events[1].body,
      .groupMessageReceived(
        PigeonGroupMessageReceivedEvent(
          groupID: Data([1]), messageID: "message", senderIdentity: Data([3]),
          body: Data("hello".utf8), replyToMessageID: "parent", epoch: 5)))
    XCTAssertEqual(
      events[2].body,
      .groupReactionReceived(
        PigeonGroupReactionReceivedEvent(
          groupID: Data([1]), messageID: "reaction", senderIdentity: Data([4]),
          targetMessageID: "message", reaction: "bird", epoch: 6)))
    XCTAssertEqual(
      events[3].body,
      .groupPolicyChanged(
        PigeonGroupPolicyChangedEvent(
          kind: .unknown(71), groupID: Data([1]), actorIdentity: Data([5]),
          subjectIdentity: Data([6]), epoch: 7, policyRevision: 8, name: "Flock",
          meshEnabled: false, relayURL: "https://relay-two.example")))
    XCTAssertEqual(
      events[4].body,
      .groupDeliveryChanged(
        PigeonGroupDeliveryChangedEvent(
          groupID: Data([1]), messageID: "message", state: .unknown(72), epoch: 9,
          deliveredCount: 2, intendedCount: 3)))
    XCTAssertEqual(
      events[5].body,
      .groupSecurityWarning(
        PigeonGroupSecurityWarningEvent(
          groupID: Data([1]), code: 10, evidenceID: Data([7]), epoch: 11)))
  }

  private func event(
    id: String,
    body: Pigeon_Wire_V1_AppEvent.OneOf_Body
  ) -> Pigeon_Wire_V1_AppEvent {
    var event = Pigeon_Wire_V1_AppEvent()
    event.version = 1
    event.eventID = id
    event.body = body
    return event
  }
}

extension PigeonCoreFacadeTests {
  func testPublicFacadeReadsSnapshotWithoutChangingGeneration() throws {
    let client = try PigeonCoreClient(identity: Identity(), store: Store())

    let snapshot = try client.stateSnapshot()

    XCTAssertEqual(snapshot, PigeonCoreSnapshot(checkpointGeneration: 0, groups: []))
    XCTAssertEqual(try client.checkpointGeneration(), 0)
  }

  func testSnapshotMapsAuthenticatedGroupProjection() {
    var group = Pigeon_Wire_V1_GroupState()
    group.groupID = Data([1])
    group.ownerIdentity = Data([2])
    group.adminIdentities = [Data([2]), Data([3])]
    group.memberIdentities = [Data([2]), Data([3]), Data([4])]
    group.name = "Birds"
    group.relayURL = "https://relay.example"
    group.coordinationID = Data([5])
    group.meshEnabled = true
    group.epoch = 6
    group.policyRevision = 7
    group.dissolved = false
    group.capabilityPublicKey = Data([8])
    group.coordinatorPublicKey = Data([9])
    var snapshot = Pigeon_Wire_V1_ClientSnapshot()
    snapshot.checkpointGeneration = 10
    snapshot.groups = [group]

    let mapped = PigeonCoreSnapshot(proto: snapshot)

    XCTAssertEqual(
      mapped,
      PigeonCoreSnapshot(
        checkpointGeneration: 10,
        groups: [
          PigeonGroupState(
            groupID: Data([1]), ownerIdentity: Data([2]),
            adminIdentities: [Data([2]), Data([3])],
            memberIdentities: [Data([2]), Data([3]), Data([4])], name: "Birds",
            relayURL: "https://relay.example", coordinationID: Data([5]),
            meshEnabled: true, epoch: 6, policyRevision: 7, dissolved: false,
            capabilityPublicKey: Data([8]), coordinatorPublicKey: Data([9]))
        ]))
  }
}
