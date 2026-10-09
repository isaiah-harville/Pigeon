import CryptoKit
import Foundation
import PigeonFFI

final class CorePeerIdentity: PlatformIdentity, @unchecked Sendable {
  let signingKey: Curve25519.Signing.PrivateKey

  init(seed: Data) throws {
    signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
  }

  func ensurePublicKey(purpose _: IdentityPurposeRequest) -> Data {
    signingKey.publicKey.rawRepresentation
  }

  func sign(purpose _: IdentityPurposeRequest, message: Data) throws -> Data {
    try signingKey.signature(for: message)
  }
}

final class InMemoryCoreCheckpointStore: CheckpointStore, @unchecked Sendable {
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

struct CorePeerFixture {
  let identity: CorePeerIdentity
  let bundle: PigeonIdentityBundle
  let prekey: PigeonPrekeyBundle
}

func makeCorePeer(seedByte: UInt8) throws -> CorePeerFixture {
  let identity = try CorePeerIdentity(seed: Data(repeating: seedByte, count: 32))
  let client = try PigeonCoreClient(
    identity: identity, store: InMemoryCoreCheckpointStore())
  _ = try client.execute(
    PigeonCoreCommand(id: "ensure-pairwise-account", body: .ensurePairwiseAccount))
  let prekey = try PigeonPrekeyBundle(decoding: client.stateSnapshot().pairwisePrekeyBundle)
  return CorePeerFixture(
    identity: identity, bundle: prekey.identityBundle, prekey: prekey)
}
