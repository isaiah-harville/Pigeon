//
//  X3DH.swift
//  PigeonCrypto
//
//  Asynchronous first contact: an X3DH-style key agreement that lets an
//  initiator (Alice) establish a session and send a first message to a
//  recipient (Bob) who is *not online*, using prekeys Bob published ahead of
//  time (in his QR identity card and/or gossiped over the mesh / left on a
//  relay).
//
//  The Noise XX handshake (NoiseHandshake.swift) is interactive: it needs both
//  peers online to complete its round trips. X3DH removes that requirement for
//  the *first* message — after it, the normal Double Ratchet takes over.
//
//  Design (Signal X3DH, https://signal.org/docs/specifications/x3dh/, adapted):
//
//  - Identity / trust reuses `IdentityBundle`: the Ed25519 identity key signs
//    the X25519 static key, and that same static key is the X3DH "identity DH
//    key" (IK). So verifying a peer's safety number (their identity key) also
//    authenticates every DH below it — no new root of trust is introduced.
//  - Bob publishes an `X3DHPrekeyBundle`: his identity bundle, a *signed
//    prekey* (SPK, rotated periodically), and optionally a *one-time prekey*
//    (OPK). Both prekeys are signed by Bob's identity key and bound to a numeric
//    id, so a relay or mesh forwarder cannot substitute its own.
//  - Alice runs `initiate(...)`: she validates the bundle, computes the four
//    (or three) DHs, derives the shared secret SK, and bootstraps the Double
//    Ratchet with Bob's signed prekey as his initial ratchet key. She emits an
//    `X3DHInitiation` header (her identity bundle + ephemeral + which prekeys
//    she used) which rides ahead of the first ratchet message.
//  - Bob runs `respond(...)` when he comes online: he looks up the private
//    prekeys named in the header, recomputes the same SK, and stands up the
//    matching ratchet end.
//
//  Replay & exhaustion (see SECURITY_MODEL.md): the one-time prekey is the
//  replay defense — Bob deletes an OPK once used, so a replayed initiation
//  yields a different SK and fails to decrypt. When OPKs are exhausted the
//  protocol still works with SPK only, at the cost of that replay resistance;
//  the SPK is rotated to bound the exposure window. Callers MUST treat OPKs as
//  one-time and rotate SPKs.
//
//  As with the rest of PigeonCrypto, all cryptographic math is delegated to
//  CryptoKit; this file only composes the primitives.
//

import CryptoKit
import Foundation

public enum X3DHError: Error, Equatable {
  case malformedBundle
  case malformedInitiation
  /// The identity↔static binding signature did not verify.
  case invalidIdentityBinding
  /// A prekey's signature did not verify against the identity key.
  case invalidPrekeySignature
  /// The initiation named a one-time prekey the responder could not supply
  /// (already used/expired) or omitted one the responder still required.
  case prekeyMismatch
  case invalidKey
}

// MARK: - Prekey bundle (published by the recipient)

/// The public prekey material a recipient publishes so others can open a
/// session without them being online. Encodes deterministically for the QR
/// card / mesh gossip / relay.
///
/// Wire layout (big-endian ids):
/// `identityBundle(128) ‖ spkID(4) ‖ spk(32) ‖ spkSig(64)
///   ‖ hasOTK(1) [ ‖ otkID(4) ‖ otk(32) ‖ otkSig(64) ]`
public struct X3DHPrekeyBundle: Equatable, Sendable {
  /// Identity key + Noise static key + binding signature (the QR identity).
  public let identity: IdentityBundle
  /// Identifier for the signed prekey, so the initiator can tell the responder
  /// which one it used (responders rotate these).
  public let signedPrekeyID: UInt32
  /// X25519 signed prekey public key (32 bytes). Also serves as the
  /// responder's initial Double Ratchet key.
  public let signedPrekey: Data
  /// Ed25519 signature by the identity key over `spkID ‖ signedPrekey`.
  public let signedPrekeySignature: Data
  /// Optional one-time prekey id.
  public let oneTimePrekeyID: UInt32?
  /// Optional X25519 one-time prekey public key (32 bytes).
  public let oneTimePrekey: Data?
  /// Ed25519 signature by the identity key over `otkID ‖ oneTimePrekey`.
  public let oneTimePrekeySignature: Data?

  public init(
    identity: IdentityBundle,
    signedPrekeyID: UInt32,
    signedPrekey: Data,
    signedPrekeySignature: Data,
    oneTimePrekeyID: UInt32? = nil,
    oneTimePrekey: Data? = nil,
    oneTimePrekeySignature: Data? = nil
  ) {
    self.identity = identity
    self.signedPrekeyID = signedPrekeyID
    self.signedPrekey = signedPrekey
    self.signedPrekeySignature = signedPrekeySignature
    self.oneTimePrekeyID = oneTimePrekeyID
    self.oneTimePrekey = oneTimePrekey
    self.oneTimePrekeySignature = oneTimePrekeySignature
  }

  /// Builds and signs a prekey bundle. The caller supplies the long-term
  /// identity signing key, the static key pair, and freshly generated prekey
  /// pairs (whose *private* halves it must retain to later `respond`).
  public static func create(
    identitySigningKey: Curve25519.Signing.PrivateKey,
    staticKey: DHKeyPair,
    signedPrekeyID: UInt32,
    signedPrekey: DHKeyPair,
    oneTimePrekeyID: UInt32? = nil,
    oneTimePrekey: DHKeyPair? = nil
  ) throws -> X3DHPrekeyBundle {
    let identityPublic = identitySigningKey.publicKey.rawRepresentation
    let staticPublic = staticKey.publicKey.rawRepresentation
    let bindingSig = try identitySigningKey.signature(for: staticPublic)
    let identity = IdentityBundle(
      identityKey: identityPublic, staticKey: staticPublic, signature: Data(bindingSig))

    let spkPublic = signedPrekey.publicKey.rawRepresentation
    let spkSig = try identitySigningKey.signature(
      for: prekeyMessage(id: signedPrekeyID, key: spkPublic))

    var otkID: UInt32?
    var otkPublic: Data?
    var otkSig: Data?
    if let oneTimePrekey, let oneTimePrekeyID {
      let pub = oneTimePrekey.publicKey.rawRepresentation
      otkID = oneTimePrekeyID
      otkPublic = pub
      otkSig = Data(
        try identitySigningKey.signature(for: prekeyMessage(id: oneTimePrekeyID, key: pub)))
    }

    return X3DHPrekeyBundle(
      identity: identity,
      signedPrekeyID: signedPrekeyID,
      signedPrekey: spkPublic,
      signedPrekeySignature: Data(spkSig),
      oneTimePrekeyID: otkID,
      oneTimePrekey: otkPublic,
      oneTimePrekeySignature: otkSig)
  }

  /// The bytes an id-bound prekey signature covers: `id(4, big-endian) ‖ key`.
  static func prekeyMessage(id: UInt32, key: Data) -> Data {
    var data = Data()
    data.append(contentsOf: withUnsafeBytes(of: id.bigEndian, Array.init))
    data.append(key)
    return data
  }

  /// Verifies the identity binding and every prekey signature. Returns `true`
  /// only if the whole bundle is authentic under the advertised identity key.
  public func isValid() -> Bool {
    guard identity.isValid() else { return false }
    guard
      let signer = try? Curve25519.Signing.PublicKey(rawRepresentation: identity.identityKey)
    else { return false }
    guard
      signer.isValidSignature(
        signedPrekeySignature, for: Self.prekeyMessage(id: signedPrekeyID, key: signedPrekey))
    else { return false }
    if let oneTimePrekey, let oneTimePrekeyID, let oneTimePrekeySignature {
      guard
        signer.isValidSignature(
          oneTimePrekeySignature,
          for: Self.prekeyMessage(id: oneTimePrekeyID, key: oneTimePrekey))
      else { return false }
    } else if oneTimePrekey != nil || oneTimePrekeyID != nil || oneTimePrekeySignature != nil {
      // Partial one-time prekey fields are malformed.
      return false
    }
    return true
  }

  // MARK: Encoding

  public func encoded() -> Data {
    var data = identity.encoded()
    data.append(contentsOf: withUnsafeBytes(of: signedPrekeyID.bigEndian, Array.init))
    data.append(signedPrekey)
    data.append(signedPrekeySignature)
    if let oneTimePrekeyID, let oneTimePrekey, let oneTimePrekeySignature {
      data.append(1)
      data.append(contentsOf: withUnsafeBytes(of: oneTimePrekeyID.bigEndian, Array.init))
      data.append(oneTimePrekey)
      data.append(oneTimePrekeySignature)
    } else {
      data.append(0)
    }
    return data
  }

  public init(decoding data: Data) throws {
    var c = ByteCursor(data)
    let identity = try IdentityBundle(
      decoding: c.take(IdentityBundle.size, X3DHError.malformedBundle))
    let spkID = try c.takeUInt32(X3DHError.malformedBundle)
    let spk = try c.take(32, X3DHError.malformedBundle)
    let spkSig = try c.take(64, X3DHError.malformedBundle)
    let hasOTK = try c.takeByte(X3DHError.malformedBundle)

    var otkID: UInt32?
    var otk: Data?
    var otkSig: Data?
    switch hasOTK {
    case 0:
      break
    case 1:
      otkID = try c.takeUInt32(X3DHError.malformedBundle)
      otk = try c.take(32, X3DHError.malformedBundle)
      otkSig = try c.take(64, X3DHError.malformedBundle)
    default:
      throw X3DHError.malformedBundle
    }
    guard c.isAtEnd else { throw X3DHError.malformedBundle }

    self.init(
      identity: identity,
      signedPrekeyID: spkID,
      signedPrekey: spk,
      signedPrekeySignature: spkSig,
      oneTimePrekeyID: otkID,
      oneTimePrekey: otk,
      oneTimePrekeySignature: otkSig)
  }
}

// MARK: - Initiation header (sent by the initiator)

/// The header the initiator sends ahead of the first ratchet message so the
/// recipient can reconstruct the same shared secret. Carries the initiator's
/// identity (for trust/safety-number verification), the X3DH ephemeral key, and
/// which of the recipient's prekeys were consumed.
///
/// Wire layout: `initiatorIdentity(128) ‖ ephemeral(32) ‖ spkID(4)
///   ‖ usedOTK(1) [ ‖ otkID(4) ]`
public struct X3DHInitiation: Equatable, Sendable {
  /// The initiator's identity bundle (its static key is X3DH's IK_A).
  public let initiatorIdentity: IdentityBundle
  /// The initiator's X25519 ephemeral public key (EK_A).
  public let ephemeralKey: Data
  /// Which signed prekey of the recipient was used.
  public let signedPrekeyID: UInt32
  /// Which one-time prekey of the recipient was used, if any.
  public let oneTimePrekeyID: UInt32?

  public init(
    initiatorIdentity: IdentityBundle,
    ephemeralKey: Data,
    signedPrekeyID: UInt32,
    oneTimePrekeyID: UInt32? = nil
  ) {
    self.initiatorIdentity = initiatorIdentity
    self.ephemeralKey = ephemeralKey
    self.signedPrekeyID = signedPrekeyID
    self.oneTimePrekeyID = oneTimePrekeyID
  }

  public func encoded() -> Data {
    var data = initiatorIdentity.encoded()
    data.append(ephemeralKey)
    data.append(contentsOf: withUnsafeBytes(of: signedPrekeyID.bigEndian, Array.init))
    if let oneTimePrekeyID {
      data.append(1)
      data.append(contentsOf: withUnsafeBytes(of: oneTimePrekeyID.bigEndian, Array.init))
    } else {
      data.append(0)
    }
    return data
  }

  public init(decoding data: Data) throws {
    var c = ByteCursor(data)
    let identity = try IdentityBundle(
      decoding: c.take(IdentityBundle.size, X3DHError.malformedInitiation))
    let ephemeral = try c.take(32, X3DHError.malformedInitiation)
    let spkID = try c.takeUInt32(X3DHError.malformedInitiation)
    let usedOTK = try c.takeByte(X3DHError.malformedInitiation)
    var otkID: UInt32?
    switch usedOTK {
    case 0:
      break
    case 1:
      otkID = try c.takeUInt32(X3DHError.malformedInitiation)
    default:
      throw X3DHError.malformedInitiation
    }
    guard c.isAtEnd else { throw X3DHError.malformedInitiation }
    self.init(
      initiatorIdentity: identity,
      ephemeralKey: ephemeral,
      signedPrekeyID: spkID,
      oneTimePrekeyID: otkID)
  }
}

// MARK: - X3DH key agreement

/// Stateless X3DH operations. The output of either side seeds a
/// `DoubleRatchetSession`, ready for normal `encrypt`/`decrypt`.
public enum X3DH {

  /// Domain separation for the shared-secret KDF.
  private static let kdfInfo = Data("Pigeon.X3DH.SharedSecret".utf8)
  /// X3DH's 32-byte 0xFF prefix (curve25519 variant) folded into the KDF input
  /// to domain-separate from any other use of these DH outputs.
  private static let kdfPrefix = Data(repeating: 0xFF, count: 32)

  /// The result of initiating: the header to transmit ahead of the first
  /// message, and the ready-to-use ratchet (call `encrypt` for the first body).
  public struct Initiation {
    public let header: X3DHInitiation
    public let session: DoubleRatchetSession
  }

  /// Initiator side (Alice). Validates `bundle`, derives the shared secret, and
  /// bootstraps the ratchet with the responder's signed prekey as its remote
  /// key. Verify `bundle.identity` against the peer's safety number before
  /// trusting the resulting session.
  public static func initiate(
    localStatic: DHKeyPair,
    localIdentity: IdentityBundle,
    bundle: X3DHPrekeyBundle
  ) throws -> Initiation {
    guard bundle.isValid() else { throw X3DHError.invalidPrekeySignature }
    guard localIdentity.isValid() else { throw X3DHError.invalidIdentityBinding }

    let ikB = try publicKey(bundle.identity.staticKey)
    let spkB = try publicKey(bundle.signedPrekey)

    let ephemeral = DHKeyPair()

    // DH1 = DH(IK_A, SPK_B); DH2 = DH(EK_A, IK_B); DH3 = DH(EK_A, SPK_B)
    var material = kdfPrefix
    material.append(try localStatic.sharedSecret(with: spkB))
    material.append(try ephemeral.sharedSecret(with: ikB))
    material.append(try ephemeral.sharedSecret(with: spkB))
    // DH4 = DH(EK_A, OPK_B) when a one-time prekey is offered.
    if let otk = bundle.oneTimePrekey {
      material.append(try ephemeral.sharedSecret(with: try publicKey(otk)))
    }

    var sharedSecret = deriveSharedSecret(material)
    defer {
      SecureMemory.zero(&material)
      SecureMemory.zero(&sharedSecret)
    }

    let session = try DoubleRatchetSession.initiator(
      sharedSecret: sharedSecret, remotePublicKey: spkB)

    let header = X3DHInitiation(
      initiatorIdentity: localIdentity,
      ephemeralKey: ephemeral.publicKey.rawRepresentation,
      signedPrekeyID: bundle.signedPrekeyID,
      oneTimePrekeyID: bundle.oneTimePrekeyID)

    return Initiation(header: header, session: session)
  }

  /// Responder side (Bob). Recomputes the shared secret from the named private
  /// prekeys and returns a ratchet ready to `decrypt` the first message.
  ///
  /// `signedPrekey` must be the private pair for `header.signedPrekeyID`.
  /// `oneTimePrekey` must be the private pair for `header.oneTimePrekeyID` (and
  /// the caller must then delete it — one-time use is the replay defense). Pass
  /// `nil` only when the header carried no one-time prekey id.
  ///
  /// The caller is still responsible for verifying `header.initiatorIdentity`
  /// against the initiator's safety number before trusting the session.
  public static func respond(
    localStatic: DHKeyPair,
    signedPrekey: DHKeyPair,
    oneTimePrekey: DHKeyPair?,
    header: X3DHInitiation
  ) throws -> DoubleRatchetSession {
    guard header.initiatorIdentity.isValid() else { throw X3DHError.invalidIdentityBinding }
    // One-time prekey presence must match what the initiator said it used.
    guard (header.oneTimePrekeyID == nil) == (oneTimePrekey == nil) else {
      throw X3DHError.prekeyMismatch
    }

    let ikA = try publicKey(header.initiatorIdentity.staticKey)
    let ekA = try publicKey(header.ephemeralKey)

    // Mirror the initiator's DHs (X25519 commutes, so swap the operands):
    // DH1 = DH(SPK_B, IK_A); DH2 = DH(IK_B, EK_A); DH3 = DH(SPK_B, EK_A)
    var material = kdfPrefix
    material.append(try signedPrekey.sharedSecret(with: ikA))
    material.append(try localStatic.sharedSecret(with: ekA))
    material.append(try signedPrekey.sharedSecret(with: ekA))
    // DH4 = DH(OPK_B, EK_A)
    if let oneTimePrekey {
      material.append(try oneTimePrekey.sharedSecret(with: ekA))
    }

    var sharedSecret = deriveSharedSecret(material)
    defer {
      SecureMemory.zero(&material)
      SecureMemory.zero(&sharedSecret)
    }

    // The signed prekey is the responder's initial ratchet key, matching the
    // initiator's `remotePublicKey`.
    return DoubleRatchetSession.responder(sharedSecret: sharedSecret, selfKeyPair: signedPrekey)
  }

  // MARK: Internals

  private static func deriveSharedSecret(_ material: Data) -> Data {
    HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: material),
      salt: Data(repeating: 0, count: 32),
      info: kdfInfo,
      outputByteCount: 32
    ).withUnsafeBytes { Data($0) }
  }

  private static func publicKey(_ raw: Data) throws -> Curve25519.KeyAgreement.PublicKey {
    do {
      return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw)
    } catch {
      throw X3DHError.invalidKey
    }
  }
}

// MARK: - Byte cursor

/// Minimal forward-only reader for the fixed wire layouts above. Throws the
/// supplied error on underflow so each decoder reports its own malformed case.
private struct ByteCursor {
  private let data: Data
  private var offset: Int

  init(_ data: Data) {
    self.data = data
    self.offset = data.startIndex
  }

  var isAtEnd: Bool { offset == data.endIndex }

  mutating func take(_ count: Int, _ error: X3DHError) throws -> Data {
    guard count >= 0, data.endIndex - offset >= count else { throw error }
    let slice = data[offset..<offset + count]
    offset += count
    return Data(slice)
  }

  mutating func takeByte(_ error: X3DHError) throws -> UInt8 {
    guard let byte = try take(1, error).first else { throw error }
    return byte
  }

  mutating func takeUInt32(_ error: X3DHError) throws -> UInt32 {
    let bytes = try take(4, error)
    var value: UInt32 = 0
    for byte in bytes { value = (value << 8) | UInt32(byte) }
    return value
  }
}
