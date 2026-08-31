//
//  CoreIdentityProvider.swift
//  Pigeon
//
//  Platform-backed identity implementation for pigeon-core. Private keys stay
//  in ThisDeviceOnly Keychain slots and only public-key/sign operations cross
//  the FFI boundary.
//

import CryptoKit
import Foundation
import PigeonFFI

protocol IdentityKeyStoreFactory {
  func makeStore(account: String) -> any KeyStore
}

private struct KeychainIdentityKeyStoreFactory: IdentityKeyStoreFactory {
  func makeStore(account: String) -> any KeyStore {
    KeychainStore(account: account)
  }
}

final class CoreIdentityProvider: PlatformIdentity, @unchecked Sendable {
  private static let mlsAccount = "identity.mls.ed25519.private"

  private let rootIdentity: IdentityManager
  private let storeFactory: any IdentityKeyStoreFactory
  private let lock = NSLock()
  private var scopedKeys: [String: Curve25519.Signing.PrivateKey] = [:]

  convenience init(rootIdentity: IdentityManager) {
    self.init(rootIdentity: rootIdentity, storeFactory: KeychainIdentityKeyStoreFactory())
  }

  init(rootIdentity: IdentityManager, storeFactory: any IdentityKeyStoreFactory) {
    self.rootIdentity = rootIdentity
    self.storeFactory = storeFactory
  }

  func ensurePublicKey(purpose: IdentityPurposeRequest) throws -> Data {
    switch purpose.kind {
    case .root, .relay:
      guard purpose.groupId.isEmpty else { throw PlatformError.InvalidOutput }
      return lock.withLock { rootIdentity.publicKey.rawRepresentation }
    case .mls, .groupCapability, .groupRecovery:
      return try scopedKey(for: purpose).publicKey.rawRepresentation
    }
  }

  func sign(purpose: IdentityPurposeRequest, message: Data) throws -> Data {
    switch purpose.kind {
    case .root, .relay:
      guard purpose.groupId.isEmpty else { throw PlatformError.InvalidOutput }
      return try lock.withLock { try rootIdentity.sign(message) }
    case .mls, .groupCapability, .groupRecovery:
      return try scopedKey(for: purpose).signature(for: message)
    }
  }

  private func scopedKey(
    for purpose: IdentityPurposeRequest
  ) throws -> Curve25519.Signing.PrivateKey {
    let account = try account(for: purpose)
    return try lock.withLock {
      if let existing = scopedKeys[account] { return existing }
      let store = storeFactory.makeStore(account: account)
      let key: Curve25519.Signing.PrivateKey
      do {
        if let stored = try store.get() {
          guard stored.count == 32 else { throw PlatformError.InvalidOutput }
          key = try Curve25519.Signing.PrivateKey(rawRepresentation: stored)
        } else {
          let generated = Curve25519.Signing.PrivateKey()
          try store.set(
            generated.rawRepresentation,
            accessibility: BackgroundDelivery.accessibility)
          guard try store.get() == generated.rawRepresentation else {
            throw PlatformError.Unavailable
          }
          key = generated
        }
      } catch let error as PlatformError {
        throw error
      } catch {
        throw PlatformError.Unavailable
      }
      scopedKeys[account] = key
      return key
    }
  }

  private func account(for purpose: IdentityPurposeRequest) throws -> String {
    switch purpose.kind {
    case .mls:
      guard purpose.groupId.isEmpty else { throw PlatformError.InvalidOutput }
      return Self.mlsAccount
    case .groupCapability, .groupRecovery:
      guard purpose.groupId.count == 32 else { throw PlatformError.InvalidOutput }
      let group = purpose.groupId.map { String(format: "%02x", $0) }.joined()
      let suffix = purpose.kind == .groupCapability ? "capability" : "recovery"
      return "identity.group.\(group).\(suffix).ed25519.private"
    case .root, .relay:
      throw PlatformError.InvalidOutput
    }
  }
}
