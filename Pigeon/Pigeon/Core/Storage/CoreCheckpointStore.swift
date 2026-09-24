//
//  CoreCheckpointStore.swift
//  Pigeon
//
//  Atomic, encrypted host storage for pigeon-core's opaque transactional state.
//

import CryptoKit
import Foundation
import PigeonFFI

struct PersistedCoreCheckpoint: Codable, Equatable {
  let generation: UInt64
  let bytes: Data
  let sha256: Data
}

/// Seals pigeon-core state with the unlocked vault key. Every replacement is
/// generation-checked and read back before success, so core never releases
/// events or ciphertext for state that the host did not persist.
final class CoreCheckpointStore: CheckpointStore, @unchecked Sendable {
  static let companionSuffix = ".core"

  private let store: EncryptedStore
  private let lock = NSLock()

  convenience init(appStore: EncryptedStore) {
    self.init(store: appStore.companion(suffix: Self.companionSuffix))
  }

  init(store: EncryptedStore) {
    self.store = store
  }

  func load() throws -> Checkpoint? {
    try lock.withLock { try loadUnlocked() }
  }

  func replace(expectedGeneration: UInt64, next: Checkpoint) throws {
    try lock.withLock {
      let (nextGeneration, overflow) = expectedGeneration.addingReportingOverflow(1)
      guard !overflow, next.generation == nextGeneration else {
        throw PlatformError.Conflict
      }
      guard Self.hasValidChecksum(next) else {
        throw PlatformError.InvalidOutput
      }

      let currentGeneration = try loadUnlocked()?.generation ?? 0
      guard currentGeneration == expectedGeneration else {
        throw PlatformError.Conflict
      }

      let persisted = PersistedCoreCheckpoint(
        generation: next.generation,
        bytes: next.bytes,
        sha256: next.sha256)
      guard store.save(persisted) else { throw PlatformError.Unavailable }
      guard try loadUnlocked() == next else { throw PlatformError.Unavailable }
    }
  }

  private func loadUnlocked() throws -> Checkpoint? {
    let persisted: PersistedCoreCheckpoint?
    do {
      persisted = try store.load(PersistedCoreCheckpoint.self)
    } catch EncryptedStoreError.authenticationFailed,
      EncryptedStoreError.invalidPayload
    {
      throw PlatformError.Corrupt
    } catch {
      throw PlatformError.Unavailable
    }

    guard let persisted else { return nil }
    let checkpoint = Checkpoint(
      generation: persisted.generation,
      bytes: persisted.bytes,
      sha256: persisted.sha256)
    guard checkpoint.generation > 0, Self.hasValidChecksum(checkpoint) else {
      throw PlatformError.Corrupt
    }
    return checkpoint
  }

  private static func hasValidChecksum(_ checkpoint: Checkpoint) -> Bool {
    checkpoint.sha256.count == SHA256.byteCount
      && checkpoint.sha256 == Data(SHA256.hash(data: checkpoint.bytes))
  }
}
