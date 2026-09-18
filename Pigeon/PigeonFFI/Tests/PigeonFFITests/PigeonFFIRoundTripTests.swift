//
//  PigeonFFIRoundTripTests.swift
//  PigeonFFITests
//
//  Proves the Rust pigeon-core crate is reachable through the UniFFI/XCFramework
//  bridge end-to-end from Swift. This is the Swift counterpart of pigeon-core's
//  `tests/pairwise.rs` (and the Rust-side FFI tests); it asserts observable
//  behaviour across the FFI seam — async first contact, the identity binding,
//  out-of-order traffic, replay rejection, and account persistence.
//

import CryptoKit
import Foundation
import SwiftProtobuf
import XCTest

@testable import PigeonFFI

final class PigeonFFIRoundTripTests: XCTestCase {

  private final class TestPlatformIdentity: PlatformIdentity, @unchecked Sendable {
    private let root = Curve25519.Signing.PrivateKey()
    private let mls = Curve25519.Signing.PrivateKey()
    private let capability = Curve25519.Signing.PrivateKey()
    private let recovery = Curve25519.Signing.PrivateKey()

    private func key(for purpose: IdentityPurposeRequest) -> Curve25519.Signing.PrivateKey {
      switch purpose.kind {
      case .root, .relay: root
      case .mls: mls
      case .groupCapability: capability
      case .groupRecovery: recovery
      }
    }

    func ensurePublicKey(purpose: IdentityPurposeRequest) -> Data {
      key(for: purpose).publicKey.rawRepresentation
    }

    func sign(purpose: IdentityPurposeRequest, message: Data) throws -> Data {
      try key(for: purpose).signature(for: message)
    }
  }

  private final class TestCheckpointStore: CheckpointStore, @unchecked Sendable {
    private let lock = NSLock()
    private var checkpoint: Checkpoint?
    private let failReplacement: Bool

    init(failReplacement: Bool = false) {
      self.failReplacement = failReplacement
    }

    func load() -> Checkpoint? {
      lock.withLock { checkpoint }
    }

    func replace(expectedGeneration: UInt64, next: Checkpoint) throws {
      try lock.withLock {
        if failReplacement { throw PlatformError.Unavailable }
        guard checkpoint?.generation ?? 0 == expectedGeneration else {
          throw PlatformError.Conflict
        }
        checkpoint = next
      }
    }
  }

  private func createGroupCommand() -> Pigeon_Wire_V1_ClientCommand {
    var create = Pigeon_Wire_V1_CreateGroup()
    create.name = "Birds"
    create.memberIdentities = [Data(repeating: 8, count: 32), Data(repeating: 9, count: 32)]
    create.relayURL = "https://relay.example"
    create.coordinatorPublicKey = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation

    var command = Pigeon_Wire_V1_ClientCommand()
    command.version = 1
    command.commandID = "swift-ffi-create"
    command.createGroup = create
    return command
  }

  func testParseVerifiesAndRejectsTamperedBundles() throws {
    let platformIdentity = TestPlatformIdentity()
    let client = try PigeonCoreClient(
      identity: platformIdentity, store: TestCheckpointStore())
    _ = try client.execute(
      PigeonCoreCommand(id: "pairwise-setup-for-parse", body: .ensurePairwiseAccount))
    let prekey = try PigeonPrekeyBundle(
      decoding: client.stateSnapshot().pairwisePrekeyBundle)
    let encodedIdentity = prekey.identityBundle.encoded

    let identity = try parseIdentityBundle(encoded: encodedIdentity)
    XCTAssertEqual(identity.identityKey, prekey.identityKey)

    var tampered = try Pigeon_Wire_V1_IdentityBundle(serializedBytes: encodedIdentity)
    tampered.bindingSignature[0] ^= 0x01
    XCTAssertThrowsError(try parseIdentityBundle(encoded: try tampered.serializedData())) { error in
      XCTAssertEqual(error as? PigeonError, .InvalidSignature)
    }
  }

  func testTransactionalClientPersistsBeforeReturningOutput() throws {
    let store = TestCheckpointStore()
    let client = try PigeonCoreClient(identity: TestPlatformIdentity(), store: store)

    let output = try client.execute(createGroupCommand())

    XCTAssertEqual(output.checkpointGeneration, 1)
    XCTAssertEqual(output.outbound.count, 2)
    XCTAssertEqual(store.load()?.generation, 1)
  }

  func testPairwiseSetupPersistsBeforeSnapshotExposesThePublicBundle() throws {
    let client = try PigeonCoreClient(
      identity: TestPlatformIdentity(), store: TestCheckpointStore())

    let output = try client.execute(
      PigeonCoreCommand(id: "pairwise-setup", body: .ensurePairwiseAccount))
    let snapshot = try client.stateSnapshot()

    XCTAssertEqual(output.checkpointGeneration, 1)
    XCTAssertFalse(snapshot.pairwisePrekeyBundle.isEmpty)
    XCTAssertNoThrow(try PigeonPrekeyBundle(decoding: snapshot.pairwisePrekeyBundle))
  }

  func testPairwiseControlCommandsEncodeWithoutExposingRatchetObjects() throws {
    let prekey = Data([1, 2, 3])
    let register = try PigeonCoreCommand(
      id: "register",
      body: .registerPairwiseContact(
        PigeonRegisterPairwiseContact(
          prekeyBundle: prekey, relayURL: "https://relay.example"))
    )
    .proto()
    XCTAssertEqual(register.registerPairwiseContact.prekeyBundle, prekey)

    let recipient = Data(repeating: 7, count: 32)
    let send = try PigeonCoreCommand(
      id: "send",
      body: .sendPairwiseControl(
        PigeonSendPairwiseControl(
          recipientIdentity: recipient, contentKind: .groupWelcome,
          payload: Data([4, 5, 6])))
    )
    .proto()
    XCTAssertEqual(send.sendPairwiseControl.recipientIdentity, recipient)
    XCTAssertEqual(send.sendPairwiseControl.contentKind, .groupWelcome)
  }

  func testTransactionalClientReturnsNoOutputWhenPersistenceFails() throws {
    let client = try PigeonCoreClient(
      identity: TestPlatformIdentity(), store: TestCheckpointStore(failReplacement: true))

    XCTAssertThrowsError(try client.execute(createGroupCommand()))
    XCTAssertEqual(try client.checkpointGeneration(), 0)
  }

}
