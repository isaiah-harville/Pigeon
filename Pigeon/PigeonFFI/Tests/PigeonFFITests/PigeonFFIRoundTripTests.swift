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

  /// Alice opens a session to Bob from a one-time prekey bundle and sends a
  /// first message; Bob establishes the matching inbound session and recovers
  /// it. Returns both accounts and the two sessions (after one reply each way).
  private func convergedPair() throws -> (
    alice: PigeonAccount, bob: PigeonAccount,
    aliceSession: PigeonSession, bobSession: PigeonSession
  ) {
    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()

    let bundle = try XCTUnwrap(bob.takeOneTimePrekeyBundles().first)
    let outbound = try alice.establishOutbound(
      peerBundle: bundle, firstPlaintext: Data("hello bob".utf8))

    let inbound = try bob.establishInbound(initiation: outbound.initiation)
    XCTAssertEqual(inbound.plaintext, Data("hello bob".utf8))

    // A reply settles the ratchet so both ends are fully converged.
    let reply = try inbound.session.encrypt(plaintext: Data("hi alice".utf8))
    XCTAssertEqual(try outbound.session.decrypt(message: reply), Data("hi alice".utf8))

    return (alice, bob, outbound.session, inbound.session)
  }

  func testFirstContactRecoversPlaintextAndVerifiedPeer() throws {
    let pair = try convergedPair()
    // Each session records the peer's verified Ed25519 identity for the
    // safety-number check — the channel is authenticated to that identity.
    XCTAssertEqual(pair.aliceSession.remoteIdentityKey(), pair.bob.identityPublicKey())
    XCTAssertEqual(pair.bobSession.remoteIdentityKey(), pair.alice.identityPublicKey())
  }

  func testFallbackPrekeyPathWorksWithoutOneTimeKeys() throws {
    let alice = try PigeonAccount.generate()
    let bob = try PigeonAccount.generate()

    let outbound = try alice.establishOutbound(
      peerBundle: bob.signedPrekeyBundle(), firstPlaintext: Data("async hi".utf8))
    let inbound = try bob.establishInbound(initiation: outbound.initiation)
    XCTAssertEqual(inbound.plaintext, Data("async hi".utf8))
  }

  func testOutOfOrderTrafficDecrypts() throws {
    let pair = try convergedPair()
    let plaintexts = ["m0", "m1", "m2", "m3", "m4"].map { Data($0.utf8) }
    let messages = try plaintexts.map { try pair.bobSession.encrypt(plaintext: $0) }

    for i in [2, 0, 4, 1, 3] {
      XCTAssertEqual(try pair.aliceSession.decrypt(message: messages[i]), plaintexts[i])
    }
  }

  func testReplayingACiphertextFails() throws {
    let pair = try convergedPair()
    let message = try pair.bobSession.encrypt(plaintext: Data("only once".utf8))
    XCTAssertEqual(try pair.aliceSession.decrypt(message: message), Data("only once".utf8))
    XCTAssertThrowsError(try pair.aliceSession.decrypt(message: message))
  }

  func testParseVerifiesAndRejectsTamperedBundles() throws {
    let account = try PigeonAccount.generate()

    let identity = try parseIdentityBundle(encoded: account.identityBundle())
    XCTAssertEqual(identity.identityKey, account.identityPublicKey())

    var tampered = try Pigeon_Wire_V1_IdentityBundle(serializedBytes: account.identityBundle())
    tampered.bindingSignature[0] ^= 0x01
    XCTAssertThrowsError(try parseIdentityBundle(encoded: try tampered.serializedData())) { error in
      XCTAssertEqual(error as? PigeonError, .InvalidSignature)
    }
  }

  func testAccountPersistenceRoundTrip() throws {
    let bob = try PigeonAccount.generate()
    let identityBefore = bob.identityPublicKey()

    let reloaded = try PigeonAccount.import(
      seed: bob.exportSeed(),
      olmPickle: bob.exportOlmPickle(),
      fallbackKey: bob.exportFallbackKey())
    XCTAssertEqual(reloaded.identityPublicKey(), identityBefore)
  }

  /// Both ends persist (pickle) and restore their sessions, then keep talking —
  /// the conversation must survive a cold start without a fresh handshake. This
  /// is the Swift counterpart of the FFI's `session_pickle_round_trips_*` test
  /// and underpins reliable store-and-forward delivery across app relaunch.
  func testSessionPersistenceRoundTripContinuesConversation() throws {
    let pair = try convergedPair()

    // Restore both ratchets from their sealed pickles, re-attaching each peer's
    // verified identity (the contact id the host keyed the session by).
    let aliceRestored = try PigeonSession.import(
      pickle: pair.aliceSession.exportPickle(),
      remoteIdentityKey: pair.bob.identityPublicKey())
    let bobRestored = try PigeonSession.import(
      pickle: pair.bobSession.exportPickle(),
      remoteIdentityKey: pair.alice.identityPublicKey())

    XCTAssertEqual(aliceRestored.remoteIdentityKey(), pair.bob.identityPublicKey())
    XCTAssertEqual(bobRestored.remoteIdentityKey(), pair.alice.identityPublicKey())

    // Traffic continues both ways over the restored sessions.
    let m1 = try aliceRestored.encrypt(plaintext: Data("after relaunch".utf8))
    XCTAssertEqual(try bobRestored.decrypt(message: m1), Data("after relaunch".utf8))
    let m2 = try bobRestored.encrypt(plaintext: Data("still here".utf8))
    XCTAssertEqual(try aliceRestored.decrypt(message: m2), Data("still here".utf8))
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
