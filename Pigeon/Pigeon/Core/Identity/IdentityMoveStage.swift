import CryptoKit
import Darwin
import Foundation

/// Destination journal. Identity seeds remain in ThisDeviceOnly Keychain slots;
/// the checkpoint and app metadata are sealed under a random staged vault key.
struct IdentityMoveStage {
  enum StageError: Error {
    case unavailable
    case invalidState
    case storageFailed
    case invalidReceipt
  }

  private struct Marker: Codable {
    let transferID: UUID
    let archiveDigest: Data
    let scopedAccounts: [String]
    var retirementSignature: Data?
    var activated: Bool
  }

  private struct Payload: Codable {
    let checkpoint: PersistedCoreCheckpoint
    let appState: PersistedState
    let relayURLs: [String]
    let scopedAccounts: [String]
  }

  private static let rootAccount = "identity-move.stage.root"
  private static let vaultAccount = "identity-move.stage.vault"
  private static let scopedPrefix = "identity-move.stage."
  private let markerURL: URL
  private let rootStore: any KeyStore
  private let vaultStore: any KeyStore

  init() throws {
    let base = try FileManager.default.url(
      for: .applicationSupportDirectory, in: .userDomainMask,
      appropriateFor: nil, create: true)
    markerURL = base.appendingPathComponent("pigeon.identity-move.marker")
    rootStore = KeychainStore(account: Self.rootAccount)
    vaultStore = KeychainStore(account: Self.vaultAccount)
  }

  var isPending: Bool { FileManager.default.fileExists(atPath: markerURL.path) }

  func pendingTransferID() throws -> UUID? {
    guard isPending else { return nil }
    return try readMarker().transferID
  }

  func hasRetirementReceipt() throws -> Bool {
    guard isPending else { return false }
    return try readMarker().retirementSignature != nil
  }

  func stagedDigest(for transferID: UUID) throws -> Data? {
    guard isPending else { return nil }
    let marker = try readMarker()
    guard marker.transferID == transferID else { throw StageError.invalidState }
    return marker.archiveDigest
  }

  func stage(_ archive: IdentityMoveArchive, digest: Data) throws {
    guard !isPending, digest.count == SHA256.byteCount,
      !IdentityManager.hasContainerEvidence,
      try !IdentityManager.storedIdentityExists()
    else { throw StageError.invalidState }
    let keyData = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    let key = SymmetricKey(data: keyData)
    let store = EncryptedStore(key: key, url: payloadURL)
    let payload = Payload(
      checkpoint: archive.checkpoint, appState: archive.appState,
      relayURLs: archive.relayURLs, scopedAccounts: archive.scopedKeySeeds.keys.sorted())
    do {
      try rootStore.set(archive.rootSeed, accessibility: .whenUnlocked)
      try vaultStore.set(keyData, accessibility: .whenUnlocked)
      for (account, seed) in archive.scopedKeySeeds {
        try KeychainStore(account: Self.scopedPrefix + account)
          .set(seed, accessibility: .whenUnlocked)
      }
      guard store.save(payload),
        try store.load(Payload.self)?.checkpoint.sha256
          == archive.checkpoint.sha256,
        try rootStore.get() == archive.rootSeed,
        try vaultStore.get() == keyData
      else { throw StageError.storageFailed }
      try synchronize(payloadURL)
      try writeMarker(
        Marker(
          transferID: archive.transferID,
          archiveDigest: digest, scopedAccounts: payload.scopedAccounts,
          retirementSignature: nil, activated: false))
    } catch {
      try? cleanup(accounts: payload.scopedAccounts)
      throw error
    }
  }

  func acceptRetirement(transferID: UUID, digest: Data, signature: Data) throws {
    var marker = try readMarker()
    guard marker.transferID == transferID, marker.archiveDigest == digest,
      marker.retirementSignature == nil,
      let root = try rootStore.get(), root.count == 32,
      let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: root).publicKey
    else { throw StageError.invalidState }
    guard
      key.isValidSignature(
        signature,
        for: Self.retirementMessage(transferID: transferID, digest: digest))
    else { throw StageError.invalidReceipt }
    marker.retirementSignature = signature
    try writeMarker(marker)
  }

  /// Idempotent after the signed receipt is durable. Startup calls this before
  /// constructing any identity or session services after an interrupted import.
  func activate() throws {
    var marker = try readMarker()
    if marker.activated {
      try cleanup(accounts: marker.scopedAccounts)
      return
    }
    guard let signature = marker.retirementSignature,
      let root = try rootStore.get(), root.count == 32,
      let signingKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: root),
      signingKey.publicKey.isValidSignature(
        signature,
        for: Self.retirementMessage(
          transferID: marker.transferID,
          digest: marker.archiveDigest)),
      let keyData = try vaultStore.get(), keyData.count == 32
    else { throw StageError.invalidState }
    let key = SymmetricKey(data: keyData)
    let sourceStore = EncryptedStore(key: key, url: payloadURL)
    guard let payload = try sourceStore.load(Payload.self),
      payload.checkpoint.sha256 == Data(SHA256.hash(data: payload.checkpoint.bytes)),
      payload.scopedAccounts.allSatisfy(CoreIdentityProvider.isScopedIdentityAccount)
    else { throw StageError.invalidState }
    try promotePayload(payload, key: key)
    try promoteKeys(payload.scopedAccounts, root: root, vaultKey: keyData)
    RelaySettings.setEntries(
      payload.relayURLs.compactMap(URL.init(string:))
        .map { RelayEntry(url: $0, enabled: true) })
    CoreCheckpointStore.markCheckpointCreated()
    IdentityManager.markContainerInitialized()
    marker.activated = true
    try writeMarker(marker)
    try cleanup(accounts: payload.scopedAccounts)
  }

  private func promotePayload(_ payload: Payload, key: SymmetricKey) throws {
    // Write checkpoint and metadata under the target DEK, then promote keys.
    // The marker blocks normal startup across every partial write.
    let appStore = EncryptedStore(key: key)
    let coreStore = appStore.companion(suffix: CoreCheckpointStore.companionSuffix)
    guard appStore.save(payload.appState), coreStore.save(payload.checkpoint),
      try appStore.load(PersistedState.self) != nil,
      try coreStore.load(PersistedCoreCheckpoint.self)?.sha256
        == payload.checkpoint.sha256
    else { throw StageError.storageFailed }
    let appURL = markerURL.deletingLastPathComponent()
      .appendingPathComponent("pigeon.store")
    try synchronize(appURL)
    try synchronize(appURL.appendingPathExtension("core"))
  }

  private func promoteKeys(_ accounts: [String], root: Data, vaultKey: Data) throws {
    try CoreIdentityProvider.deleteStoredScopedKeys()
    for account in accounts {
      let staged = KeychainStore(account: Self.scopedPrefix + account)
      guard let seed = try staged.get(), seed.count == 32 else {
        throw StageError.invalidState
      }
      let active = KeychainStore(account: account)
      try active.set(seed, accessibility: .whenUnlocked)
      guard try active.get() == seed else { throw StageError.storageFailed }
    }
    let activeRoot = try IdentityManager(creationPolicy: .allowCreation)
    try activeRoot.replaceIdentity(with: root)
    try Vault.replaceStoredKeyAfterCleanSlate(with: vaultKey)
  }

  private var payloadURL: URL {
    markerURL.deletingLastPathComponent()
      .appendingPathComponent("pigeon.identity-move.payload")
  }

  private func readMarker() throws -> Marker {
    guard isPending else { throw StageError.invalidState }
    return try PropertyListDecoder().decode(
      Marker.self,
      from: Data(contentsOf: markerURL))
  }

  private func writeMarker(_ marker: Marker) throws {
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    try encoder.encode(marker).write(
      to: markerURL,
      options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    try synchronize(markerURL)
  }

  private func synchronize(_ url: URL) throws {
    let handle = try FileHandle(forWritingTo: url)
    try handle.synchronize()
    try handle.close()
    let directory = open(url.deletingLastPathComponent().path, O_RDONLY)
    guard directory >= 0 else { throw StageError.storageFailed }
    defer { close(directory) }
    guard fsync(directory) == 0 else { throw StageError.storageFailed }
  }

  private func cleanup(accounts: [String]) throws {
    for account in accounts {
      try KeychainStore(account: Self.scopedPrefix + account).delete()
    }
    try rootStore.delete()
    try vaultStore.delete()
    guard EncryptedStore(key: SymmetricKey(size: .bits256), url: payloadURL).wipe()
    else { throw StageError.storageFailed }
    if isPending { try FileManager.default.removeItem(at: markerURL) }
  }
}

extension IdentityMoveStage {
  func discardUnretired() throws {
    guard isPending else { return }
    let marker = try readMarker()
    guard marker.retirementSignature == nil else { throw StageError.invalidState }
    let accounts: [String]
    if let key = try vaultStore.get(),
      let payload = try EncryptedStore(key: SymmetricKey(data: key), url: payloadURL)
        .load(Payload.self)
    {
      accounts = payload.scopedAccounts
    } else {
      accounts = []
    }
    try cleanup(accounts: accounts)
  }

  static func retirementMessage(transferID: UUID, digest: Data) -> Data {
    Data("pigeon.identity-move.retired.v1".utf8)
      + Data(transferID.uuidString.lowercased().utf8) + digest
  }

}
