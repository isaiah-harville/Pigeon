import Foundation
import PigeonFFI

extension SessionPersistence {
  static func legacyPairwiseMigration(
    _ crypto: PersistedCrypto
  ) throws -> PigeonLegacyPairwiseMigration? {
    guard let accountState = crypto.olmAccountPickle,
      let fallbackKey = crypto.olmFallbackKey
    else {
      guard crypto.olmAccountPickle == nil, crypto.olmFallbackKey == nil else {
        throw SessionPersistenceError.invalidCryptoState
      }
      return nil
    }
    let sessions: [PigeonLegacyPairwiseSession] = try crypto.sessions.compactMap { element in
      let (key, entry) = element
      guard let state = entry.pickle else { return nil }
      guard let identity = Data(base64Encoded: key), identity.count == 32 else {
        throw SessionPersistenceError.invalidCryptoState
      }
      return PigeonLegacyPairwiseSession(remoteIdentity: identity, state: state)
    }
    return PigeonLegacyPairwiseMigration(
      accountState: accountState, fallbackKey: fallbackKey, sessions: sessions)
  }
}

extension SessionManager {
  func migrateLegacyPairwiseStateIfNeeded(
    _ migration: PigeonLegacyPairwiseMigration?, into coreClient: PigeonCoreClient
  ) throws {
    guard let migration,
      try coreClient.stateSnapshot().pairwisePrekeyBundle.isEmpty
    else { return }
    _ = try coreClient.execute(
      PigeonCoreCommand(
        id: "migrate-legacy-pairwise-v1",
        body: .migrateLegacyPairwiseState(migration)))
  }
}
