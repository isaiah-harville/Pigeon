//
//  CleanSlateExecutor.swift
//  Pigeon
//
//  Orders irreversible local-data deletion before trust-root rotation.
//

import CryptoKit
import Darwin
import Foundation

enum CleanSlateError: Error, Equatable {
  case wipeFailed
  case identityRotationFailed
  case vaultRotationFailed
  case recoveryStateFailed
  case serviceRestartFailed
}

enum CleanSlateExecutor {
  static func run(
    wipe: () -> Bool,
    rotateIdentity: () throws -> Void,
    rotateVault: () throws -> Void
  ) throws {
    guard wipe() else { throw CleanSlateError.wipeFailed }
    do {
      try rotateIdentity()
    } catch {
      throw CleanSlateError.identityRotationFailed
    }
    do {
      try rotateVault()
    } catch {
      throw CleanSlateError.vaultRotationFailed
    }
  }
}

/// Durable intent for an authenticated Clean Slate operation. It is set before
/// the first deletion and cleared only after data and both trust roots rotate.
/// A crash therefore resumes the reset instead of starting an ambiguous graph.
struct CleanSlateRecovery {
  private static let pendingMarker = Data("pending-v1".utf8)
  private static let cleanupMarker = Data("cleanup-v1".utf8)
  private static let identityStageAccount = "clean-slate.identity.target"
  private static let vaultStageAccount = "clean-slate.vault.target"

  private let url: URL?
  private let identityStage: any KeyStore
  private let vaultStage: any KeyStore

  init() {
    let base = try? FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: true)
    self.url = base?.appendingPathComponent("pigeon.clean-slate")
    self.identityStage = KeychainStore(account: Self.identityStageAccount)
    self.vaultStage = KeychainStore(account: Self.vaultStageAccount)
  }

  init(url: URL, identityStage: any KeyStore, vaultStage: any KeyStore) {
    self.url = url
    self.identityStage = identityStage
    self.vaultStage = vaultStage
  }

  var isPending: Bool {
    guard let url else { return false }
    return FileManager.default.fileExists(atPath: url.path)
  }

  func begin() throws {
    if isPending {
      guard try markerData() == Self.pendingMarker else {
        throw CleanSlateError.recoveryStateFailed
      }
      _ = try targets()
      return
    }
    guard let url else { throw CleanSlateError.recoveryStateFailed }
    // Orphaned staging items can only precede the marker, so no destructive
    // action ever depended on them. Replace them before starting a new reset.
    try identityStage.delete()
    try vaultStage.delete()
    try identityStage.set(Self.randomKey(), accessibility: .whenUnlocked)
    try vaultStage.set(Self.randomKey(), accessibility: .whenUnlocked)
    do {
      try Self.pendingMarker.write(
        to: url,
        options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
      try Self.synchronize(url)
    } catch {
      try? identityStage.delete()
      try? vaultStage.delete()
      throw CleanSlateError.recoveryStateFailed
    }
  }

  func finish() throws {
    guard let url else { throw CleanSlateError.recoveryStateFailed }
    try Self.cleanupMarker.write(
      to: url,
      options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    try Self.synchronize(url)
    _ = try finishCleanupIfNeeded()
  }

  /// Completes only the post-promotion secret cleanup. A durable cleanup marker
  /// lets a retry remove staging items without rotating either trust root again.
  @discardableResult
  func finishCleanupIfNeeded() throws -> Bool {
    guard isPending, try markerData() == Self.cleanupMarker else { return false }
    try identityStage.delete()
    try vaultStage.delete()
    guard try identityStage.get() == nil, try vaultStage.get() == nil else {
      throw CleanSlateError.recoveryStateFailed
    }
    guard let url else { throw CleanSlateError.recoveryStateFailed }
    try FileManager.default.removeItem(at: url)
    try Self.synchronizeDirectory(url.deletingLastPathComponent())
    return true
  }

  func targets() throws -> (identitySeed: Data, vaultKey: Data) {
    guard let identitySeed = try identityStage.get(), identitySeed.count == 32,
      let vaultKey = try vaultStage.get(), vaultKey.count == 32
    else { throw CleanSlateError.recoveryStateFailed }
    return (identitySeed, vaultKey)
  }

  private static func randomKey() -> Data {
    SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
  }

  private func markerData() throws -> Data {
    guard let url else { throw CleanSlateError.recoveryStateFailed }
    return try Data(contentsOf: url)
  }

  private static func synchronize(_ url: URL) throws {
    let handle = try FileHandle(forWritingTo: url)
    try handle.synchronize()
    try handle.close()
    try synchronizeDirectory(url.deletingLastPathComponent())
  }

  private static func synchronizeDirectory(_ url: URL) throws {
    let descriptor = open(url.path, O_RDONLY)
    guard descriptor >= 0 else { throw CleanSlateError.recoveryStateFailed }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw CleanSlateError.recoveryStateFailed }
  }
}
