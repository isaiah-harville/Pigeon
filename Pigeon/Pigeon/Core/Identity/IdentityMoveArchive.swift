import CryptoKit
import Foundation

enum IdentityMoveArchiveError: Error, Equatable {
  case invalidArchive
  case oversizedArchive
}

/// An in-memory move payload. The channel encrypts it; destination identity
/// seeds go to Keychain slots and the checkpoint is sealed under a staged DEK.
struct IdentityMoveArchive: Codable {
  static let version: UInt32 = 1
  static let maximumEncodedBytes = 96 * 1024 * 1024

  let formatVersion: UInt32
  let transferID: UUID
  let rootSeed: Data
  let scopedKeySeeds: [String: Data]
  let checkpoint: PersistedCoreCheckpoint
  let appState: PersistedState
  let relayURLs: [String]

  init(
    transferID: UUID, rootSeed: Data, scopedKeySeeds: [String: Data],
    checkpoint: PersistedCoreCheckpoint, appState: PersistedState,
    relayURLs: [String]
  ) throws {
    var state = appState
    state.conversations.removeAll()
    state.groupConversations = state.groupConversations.mapValues { conversation in
      var withoutHistory = conversation
      withoutHistory.messages.removeAll()
      return withoutHistory
    }
    state.olmAccountPickle = nil
    state.olmFallbackKey = nil
    self.formatVersion = Self.version
    self.transferID = transferID
    self.rootSeed = rootSeed
    self.scopedKeySeeds = scopedKeySeeds
    self.checkpoint = checkpoint
    self.appState = state
    self.relayURLs = relayURLs
    try validate()
  }

  func encode() throws -> Data {
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    let bytes = try encoder.encode(self)
    guard bytes.count <= Self.maximumEncodedBytes else {
      throw IdentityMoveArchiveError.oversizedArchive
    }
    return bytes
  }

  static func decode(_ bytes: Data) throws -> Self {
    guard bytes.count <= maximumEncodedBytes else {
      throw IdentityMoveArchiveError.oversizedArchive
    }
    let archive = try PropertyListDecoder().decode(Self.self, from: bytes)
    try archive.validate()
    return archive
  }

  private func validate() throws {
    guard formatVersion == Self.version, rootSeed.count == 32,
      checkpoint.generation > 0,
      checkpoint.sha256 == Data(SHA256.hash(data: checkpoint.bytes)),
      checkpoint.bytes.count <= 64 * 1024 * 1024,
      appState.conversations.isEmpty,
      appState.groupConversations.values.allSatisfy(\.messages.isEmpty),
      appState.olmAccountPickle == nil, appState.olmFallbackKey == nil,
      scopedKeySeeds.allSatisfy({ account, seed in
        CoreIdentityProvider.isScopedIdentityAccount(account) && seed.count == 32
      }),
      relayURLs.count <= 8,
      relayURLs.allSatisfy({ value in
        guard let url = URL(string: value),
          let scheme = url.scheme?.lowercased(),
          scheme == "ws" || scheme == "wss",
          url.host?.isEmpty == false, url.user == nil, url.password == nil
        else { return false }
        return true
      })
    else { throw IdentityMoveArchiveError.invalidArchive }
  }
}
