//
//  DoubleRatchet.swift
//  PigeonCrypto
//
//  A clean-room implementation of the Signal Double Ratchet algorithm,
//  following the specification at https://signal.org/docs/specifications/doubleratchet/.
//
//  The ratchet gives each message its own key (forward secrecy) and heals
//  after a compromise as soon as a fresh DH ratchet step occurs
//  (post-compromise security). It tolerates out-of-order and dropped
//  messages via stored "skipped" message keys — essential over an
//  unreliable Bluetooth mesh.
//
//  This composes the audited CryptoKit primitives in `Primitives.swift`;
//  it does not implement any cryptographic math itself.
//

import CryptoKit
import Foundation

/// Errors thrown by the ratchet.
public enum RatchetError: Error, Equatable {
  /// A message would require skipping more keys than `maxSkip` allows —
  /// likely an attack or hopelessly lost chain, so we refuse.
  case tooManySkippedMessages
  /// The message header could not be decoded.
  case malformedHeader
  /// AEAD authentication failed (tampering, wrong key, or replay).
  case decryptionFailed
}

/// The plaintext header that travels with every ratchet message. It is not
/// secret, but it is authenticated: it is folded into the AEAD associated
/// data, so tampering breaks decryption.
public struct RatchetHeader: Equatable, Sendable {
  /// Sender's current DH ratchet public key (raw 32 bytes).
  public let dhPublic: Data
  /// Number of messages in the sender's *previous* sending chain.
  public let previousChainLength: UInt32
  /// Message number within the sender's current sending chain.
  public let messageNumber: UInt32

  /// Fixed 40-byte wire encoding: 32-byte key ‖ PN (big-endian u32) ‖ N (big-endian u32).
  public func encoded() -> Data {
    var data = dhPublic
    data.append(contentsOf: withUnsafeBytes(of: previousChainLength.bigEndian, Array.init))
    data.append(contentsOf: withUnsafeBytes(of: messageNumber.bigEndian, Array.init))
    return data
  }

  public init(dhPublic: Data, previousChainLength: UInt32, messageNumber: UInt32) {
    self.dhPublic = dhPublic
    self.previousChainLength = previousChainLength
    self.messageNumber = messageNumber
  }

  public init(decoding data: Data) throws {
    guard data.count == 40 else { throw RatchetError.malformedHeader }
    let base = data.startIndex
    self.dhPublic = data[base..<base + 32]
    self.previousChainLength = loadBigEndianUInt32(data[(base + 32)..<(base + 36)])
    self.messageNumber = loadBigEndianUInt32(data[(base + 36)..<(base + 40)])
  }
}

/// A complete ratchet message: authenticated header plus AEAD ciphertext.
public struct RatchetMessage: Equatable, Sendable {
  public let header: RatchetHeader
  public let ciphertext: Data

  public init(header: RatchetHeader, ciphertext: Data) {
    self.header = header
    self.ciphertext = ciphertext
  }
}

/// One end of a Double Ratchet conversation. Holds mutable secret state and is
/// therefore a reference type used from a single isolation domain at a time.
public final class DoubleRatchetSession {

  /// Identifies a stored message key for an out-of-order message.
  private struct SkippedKeyID: Hashable {
    let dhPublic: Data
    let messageNumber: UInt32
  }

  /// Safety cap on how many message keys we'll skip (and store) in response to
  /// a single message, bounding memory and resisting a malicious gap.
  public let maxSkip: Int

  // Ratchet state (names follow the spec).
  private var dhSelf: DHKeyPair  // DHs
  private var dhRemote: Curve25519.KeyAgreement.PublicKey?  // DHr
  private var rootKey: Data  // RK
  private var sendingChainKey: Data?  // CKs
  private var receivingChainKey: Data?  // CKr
  private var sendCount: UInt32 = 0  // Ns
  private var receiveCount: UInt32 = 0  // Nr
  private var previousSendCount: UInt32 = 0  // PN
  private var skipped: [SkippedKeyID: Data] = [:]  // MKSKIPPED

  private init(
    dhSelf: DHKeyPair,
    dhRemote: Curve25519.KeyAgreement.PublicKey?,
    rootKey: Data,
    sendingChainKey: Data?,
    maxSkip: Int
  ) {
    self.dhSelf = dhSelf
    self.dhRemote = dhRemote
    self.rootKey = rootKey
    self.sendingChainKey = sendingChainKey
    self.maxSkip = maxSkip
  }

  /// Initializes the side that sends first (Alice). Requires a shared secret
  /// from the handshake and the responder's initial ratchet public key.
  public static func initiator(
    sharedSecret: Data,
    remotePublicKey: Curve25519.KeyAgreement.PublicKey,
    maxSkip: Int = 1000
  ) throws -> DoubleRatchetSession {
    let dhSelf = DHKeyPair()
    let dhOut = try dhSelf.sharedSecret(with: remotePublicKey)
    let (rk, cks) = Primitives.kdfRootKey(rootKey: sharedSecret, dhOutput: dhOut)
    return DoubleRatchetSession(
      dhSelf: dhSelf,
      dhRemote: remotePublicKey,
      rootKey: rk,
      sendingChainKey: cks,
      maxSkip: maxSkip)
  }

  /// Initializes the side that receives first (Bob). Uses the same shared
  /// secret and the ratchet key pair whose public half was given to the initiator.
  public static func responder(
    sharedSecret: Data,
    selfKeyPair: DHKeyPair,
    maxSkip: Int = 1000
  ) -> DoubleRatchetSession {
    DoubleRatchetSession(
      dhSelf: selfKeyPair,
      dhRemote: nil,
      rootKey: sharedSecret,
      sendingChainKey: nil,
      maxSkip: maxSkip)
  }

  /// This side's current ratchet public key (what the peer needs to start as initiator).
  public var publicKey: Curve25519.KeyAgreement.PublicKey { dhSelf.publicKey }

  // MARK: - Encrypt

  /// Encrypts `plaintext`, advancing the sending chain by one step.
  /// `associatedData` (optional, e.g. transport metadata) is authenticated
  /// alongside the header but not encrypted.
  public func encrypt(_ plaintext: Data, associatedData: Data = Data()) throws -> RatchetMessage {
    guard let cks = sendingChainKey else {
      // Should never happen: the sending chain is established at init or
      // after the first DH ratchet step.
      throw RatchetError.decryptionFailed
    }
    // Destructuring gives `messageKey` sole ownership of its buffer, so it can
    // be wiped after use (the tuple form avoids a lingering aliasing copy).
    var (nextCK, messageKey) = Primitives.kdfChainKey(chainKey: cks)
    sendingChainKey = nextCK
    defer { SecureMemory.zero(&messageKey) }

    let header = RatchetHeader(
      dhPublic: dhSelf.publicKey.rawRepresentation,
      previousChainLength: previousSendCount,
      messageNumber: sendCount)
    sendCount += 1

    let ad = associatedData + header.encoded()
    let ciphertext = try Primitives.encrypt(
      plaintext: plaintext, messageKey: messageKey, associatedData: ad)
    return RatchetMessage(header: header, ciphertext: ciphertext)
  }

  // MARK: - Decrypt

  /// Decrypts `message`, performing a DH ratchet step and/or skipping message
  /// keys as the header dictates. Handles out-of-order and dropped messages.
  public func decrypt(_ message: RatchetMessage, associatedData: Data = Data()) throws -> Data {
    let header = message.header

    // 1. A previously skipped key may already cover this message.
    if let plaintext = try decryptWithSkippedKey(message, associatedData: associatedData) {
      return plaintext
    }

    // 2. New DH ratchet public key -> finish the old receiving chain, then step.
    if dhRemote?.rawRepresentation != header.dhPublic {
      try skipMessageKeys(until: header.previousChainLength)
      try dhRatchet(header: header)
    }

    // 3. Skip any gap within the current receiving chain.
    try skipMessageKeys(until: header.messageNumber)

    // 4. Derive this message's key and advance the receiving chain.
    guard let ckr = receivingChainKey else { throw RatchetError.decryptionFailed }
    var (nextCK, messageKey) = Primitives.kdfChainKey(chainKey: ckr)
    receivingChainKey = nextCK
    receiveCount += 1
    defer { SecureMemory.zero(&messageKey) }

    let ad = associatedData + header.encoded()
    do {
      return try Primitives.decrypt(
        ciphertext: message.ciphertext, messageKey: messageKey, associatedData: ad)
    } catch {
      throw RatchetError.decryptionFailed
    }
  }

  // MARK: - Internals

  private func decryptWithSkippedKey(_ message: RatchetMessage, associatedData: Data) throws
    -> Data?
  {
    let id = SkippedKeyID(
      dhPublic: message.header.dhPublic, messageNumber: message.header.messageNumber)
    guard var messageKey = skipped[id] else { return nil }
    let ad = associatedData + message.header.encoded()
    let plaintext: Data
    do {
      plaintext = try Primitives.decrypt(
        ciphertext: message.ciphertext, messageKey: messageKey, associatedData: ad)
    } catch {
      throw RatchetError.decryptionFailed  // key kept for a later retry
    }
    skipped[id] = nil  // each message key is used exactly once
    // The dict reference is now gone, so this local solely owns the buffer; wipe it.
    SecureMemory.zero(&messageKey)
    return plaintext
  }

  /// Advances the receiving chain up to `until`, stashing each skipped message
  /// key so a late-arriving message can still be decrypted.
  private func skipMessageKeys(until: UInt32) throws {
    guard let ckr = receivingChainKey, let dhr = dhRemote else { return }
    guard until <= receiveCount || Int(until - receiveCount) <= maxSkip else {
      throw RatchetError.tooManySkippedMessages
    }
    var chainKey = ckr
    while receiveCount < until {
      let (nextCK, messageKey) = Primitives.kdfChainKey(chainKey: chainKey)
      skipped[SkippedKeyID(dhPublic: dhr.rawRepresentation, messageNumber: receiveCount)] =
        messageKey
      chainKey = nextCK
      receiveCount += 1
    }
    receivingChainKey = chainKey
  }

  /// Performs a DH ratchet step: derive a new receiving chain from the peer's
  /// new key, rotate our own DH key, and derive a new sending chain.
  private func dhRatchet(header: RatchetHeader) throws {
    previousSendCount = sendCount
    sendCount = 0
    receiveCount = 0

    let remote = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: header.dhPublic)
    dhRemote = remote

    let (rk1, ckr) = Primitives.kdfRootKey(
      rootKey: rootKey, dhOutput: try dhSelf.sharedSecret(with: remote))
    rootKey = rk1
    receivingChainKey = ckr

    dhSelf = DHKeyPair()
    let (rk2, cks) = Primitives.kdfRootKey(
      rootKey: rootKey, dhOutput: try dhSelf.sharedSecret(with: remote))
    rootKey = rk2
    sendingChainKey = cks
  }
}

/// Reads the first 4 bytes of the slice as a big-endian UInt32.
private func loadBigEndianUInt32(_ data: Data.SubSequence) -> UInt32 {
  var value: UInt32 = 0
  for byte in data { value = (value << 8) | UInt32(byte) }
  return value
}
