//
//  IdentityManager.swift
//  Pigeon
//
//  Owns the device's long-term identity: the Ed25519 identity key and the
//  X25519 Noise static key bound to it.
//

import CryptoKit
import Foundation
import PigeonCrypto

/// Creates and holds the device's long-term keys.
///
/// Two long-term keys, both generated on first launch and stored in the
/// Keychain (never leaving the device):
/// - an **Ed25519 identity key** — the root of trust, basis of the fingerprint
///   and safety number;
/// - an **X25519 Noise static key** — used by the handshake — whose public half
///   is **signed by the identity key** so the two are cryptographically bound.
///
/// Curve25519 (rather than Secure Enclave's P-256) is deliberate: it is the
/// curve the Noise + Double Ratchet stack requires.
@Observable
final class IdentityManager {

  private static let identityAccount = "identity.ed25519.private"
  private static let staticAccount = "noise.static.x25519.private"
  private static let signedPrekeyAccount = "x3dh.signedprekey.v1"

  /// How long a signed prekey is advertised before it rotates. The previous
  /// prekey is retained one extra interval so in-flight X3DH initiations that
  /// referenced it still resolve, bounding the async first-contact exposure
  /// window — see SECURITY_MODEL.md §5.7.
  private static let signedPrekeyLifetime: TimeInterval = 7 * 24 * 60 * 60

  private let store: KeychainStore
  private let staticStore: KeychainStore
  private let prekeyStore: KeychainStore
  private var privateKey: Curve25519.Signing.PrivateKey
  private var staticKeyPair: DHKeyPair
  /// Signed-prekey lifecycle state for X3DH async first contact (current +
  /// previous, with the current key's birth time for rotation).
  private var signedPrekeys: SignedPrekeyState

  /// The public identity safe to share with peers (Ed25519).
  var publicKey: IdentityPublicKey {
    IdentityPublicKey(signingKey: privateKey.publicKey)
  }

  /// The X25519 Noise static key pair used to establish encrypted sessions.
  var noiseStaticKey: DHKeyPair { staticKeyPair }

  /// The signed, shareable identity bundle (Ed25519 identity ‖ X25519 static ‖
  /// signature). This is what we encode into our QR code.
  var identityBundle: IdentityBundle {
    let staticPub = staticKeyPair.publicKey.rawRepresentation
    // Signing our own static key cannot fail with a valid identity key.
    let signature = (try? privateKey.signature(for: staticPub)) ?? Data()
    return IdentityBundle(
      identityKey: privateKey.publicKey.rawRepresentation,
      staticKey: staticPub,
      signature: signature)
  }

  /// Loads existing keys, generating and persisting any that are missing.
  convenience init() throws {
    try self.init(
      store: KeychainStore(account: IdentityManager.identityAccount),
      staticStore: KeychainStore(account: IdentityManager.staticAccount))
  }

  init(
    store: KeychainStore,
    staticStore: KeychainStore,
    prekeyStore: KeychainStore = KeychainStore(account: IdentityManager.signedPrekeyAccount)
  ) throws {
    self.store = store
    self.staticStore = staticStore
    self.prekeyStore = prekeyStore

    // New keys adopt the accessibility implied by the background-delivery
    // preference (default: readable in a locked background launch).
    let accessibility = BackgroundDelivery.accessibility

    if let existing = try store.get() {
      self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: existing)
    } else {
      let fresh = Curve25519.Signing.PrivateKey()
      try store.set(fresh.rawRepresentation, accessibility: accessibility)
      self.privateKey = fresh
    }

    if let existingStatic = try staticStore.get() {
      let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: existingStatic)
      self.staticKeyPair = DHKeyPair(privateKey: key)
    } else {
      let fresh = DHKeyPair()
      try staticStore.set(fresh.privateKey.rawRepresentation, accessibility: accessibility)
      self.staticKeyPair = fresh
    }

    // Load (or generate) the signed prekey, rotating it if it has aged out.
    let loaded = (try? prekeyStore.get()).flatMap { $0 }.flatMap(SignedPrekeyState.init(decoding:))
    if let loaded {
      self.signedPrekeys = loaded
    } else {
      self.signedPrekeys = SignedPrekeyState.fresh(id: 1)
      try? prekeyStore.set(signedPrekeys.encoded(), accessibility: accessibility)
    }
    rotateSignedPrekeyIfNeeded()
  }

  // MARK: - X3DH signed prekeys

  /// The prekey bundle we publish (in the QR card) so peers can open a session
  /// asynchronously. SPK-only: one-time prekeys aren't carried in the static QR
  /// (the same code is shown repeatedly, so an OPK couldn't stay one-time); the
  /// `X3DH` core supports OPKs for a future relay-served path. See §5.7.
  var publishedPrekeyBundle: X3DHPrekeyBundle? {
    try? X3DHPrekeyBundle.create(
      identitySigningKey: privateKey,
      staticKey: staticKeyPair,
      signedPrekeyID: signedPrekeys.current.id,
      signedPrekey: signedPrekeys.current.keyPair)
  }

  /// The private signed-prekey pair for `id` (current or the retained previous),
  /// or `nil` if we no longer hold it (rotated out) — used when responding to an
  /// X3DH initiation that named one of our prekeys.
  func signedPrekey(forID id: UInt32) -> DHKeyPair? {
    if id == signedPrekeys.current.id { return signedPrekeys.current.keyPair }
    if let previous = signedPrekeys.previous, id == previous.id { return previous.keyPair }
    return nil
  }

  /// Rotates the signed prekey when the current one has outlived its lifetime:
  /// the current becomes `previous` (kept for in-flight initiations) and a fresh
  /// current is generated. Idempotent and cheap to call on launch.
  private func rotateSignedPrekeyIfNeeded() {
    guard
      Date().timeIntervalSince1970 - signedPrekeys.current.createdAt
        >= Self.signedPrekeyLifetime
    else { return }
    let nextID = signedPrekeys.current.id &+ 1
    signedPrekeys = SignedPrekeyState(
      current: SignedPrekey(
        id: nextID, createdAt: Date().timeIntervalSince1970, keyPair: DHKeyPair()),
      previous: signedPrekeys.current)
    try? prekeyStore.set(signedPrekeys.encoded(), accessibility: BackgroundDelivery.accessibility)
  }

  /// Rewrites both long-term keys under a new keychain accessibility class.
  /// Must be called while the device is unlocked (the keys have to be readable
  /// to rewrite them). Used when the user toggles background delivery.
  func applyKeychainAccessibility(_ accessibility: KeychainAccessibility) throws {
    try store.setAccessibility(accessibility)
    try staticStore.setAccessibility(accessibility)
  }

  /// Signs `data` with the identity key.
  func sign(_ data: Data) throws -> Data {
    try privateKey.signature(for: data)
  }

  /// Destroys the current identity and static key and generates fresh ones.
  /// Irreversible: all existing trust relationships become invalid.
  func resetIdentity() throws {
    let accessibility = BackgroundDelivery.accessibility
    let fresh = Curve25519.Signing.PrivateKey()
    try store.set(fresh.rawRepresentation, accessibility: accessibility)
    self.privateKey = fresh

    let freshStatic = DHKeyPair()
    try staticStore.set(freshStatic.privateKey.rawRepresentation, accessibility: accessibility)
    self.staticKeyPair = freshStatic

    // Drop the old signed prekeys with the identity they were bound to.
    self.signedPrekeys = SignedPrekeyState.fresh(id: 1)
    try? prekeyStore.set(signedPrekeys.encoded(), accessibility: accessibility)
  }
}

// MARK: - Signed prekey storage

/// One signed prekey: its numeric id, birth time (for rotation), and private
/// X25519 key pair. Only the private key is persisted as secret material.
private struct SignedPrekey {
  let id: UInt32
  let createdAt: TimeInterval
  let keyPair: DHKeyPair
}

/// The persisted signed-prekey state: the current key plus the one previous key
/// retained so initiations referencing the just-rotated key still resolve.
///
/// Keychain blob: `version(1) ‖ currentID(4,BE) ‖ currentCreatedAt(8,BE bits)
///   ‖ currentPriv(32) ‖ hasPrev(1) [ ‖ prevID(4,BE) ‖ prevPriv(32) ]`.
private struct SignedPrekeyState {
  var current: SignedPrekey
  var previous: SignedPrekey?

  private static let version: UInt8 = 1

  static func fresh(id: UInt32) -> SignedPrekeyState {
    SignedPrekeyState(
      current: SignedPrekey(
        id: id, createdAt: Date().timeIntervalSince1970, keyPair: DHKeyPair()),
      previous: nil)
  }

  func encoded() -> Data {
    var data = Data([Self.version])
    appendPrekey(&data, current, includeTime: true)
    if let previous {
      data.append(1)
      appendPrekey(&data, previous, includeTime: false)
    } else {
      data.append(0)
    }
    return data
  }

  init(current: SignedPrekey, previous: SignedPrekey?) {
    self.current = current
    self.previous = previous
  }

  init?(decoding data: Data) {
    var c = data.startIndex
    func take(_ n: Int) -> Data? {
      guard data.endIndex - c >= n else { return nil }
      defer { c += n }
      return Data(data[c..<c + n])
    }
    func u32(_ d: Data) -> UInt32 { d.reduce(0) { ($0 << 8) | UInt32($1) } }
    func u64(_ d: Data) -> UInt64 { d.reduce(0) { ($0 << 8) | UInt64($1) } }

    guard let version = take(1), version.first == Self.version,
      let curID = take(4), let curTime = take(8), let curPriv = take(32),
      let curKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: curPriv),
      let hasPrev = take(1)?.first
    else { return nil }

    self.current = SignedPrekey(
      id: u32(curID),
      createdAt: TimeInterval(bitPattern: u64(curTime)),
      keyPair: DHKeyPair(privateKey: curKey))

    switch hasPrev {
    case 0:
      self.previous = nil
    case 1:
      guard let prevID = take(4), let prevPriv = take(32),
        let prevKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: prevPriv)
      else { return nil }
      // Previous key's birth time is irrelevant (never re-published); use 0.
      self.previous = SignedPrekey(
        id: u32(prevID), createdAt: 0, keyPair: DHKeyPair(privateKey: prevKey))
    default:
      return nil
    }
  }

  private func appendPrekey(_ data: inout Data, _ prekey: SignedPrekey, includeTime: Bool) {
    data.append(contentsOf: withUnsafeBytes(of: prekey.id.bigEndian, Array.init))
    if includeTime {
      data.append(
        contentsOf: withUnsafeBytes(of: prekey.createdAt.bitPattern.bigEndian, Array.init))
    }
    data.append(prekey.keyPair.privateKey.rawRepresentation)
  }
}
