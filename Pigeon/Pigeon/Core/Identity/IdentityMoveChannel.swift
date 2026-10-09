import CryptoKit
import Foundation

enum IdentityMoveChannelError: Error, Equatable {
  case invalidPeerKey
  case unavailable
  case invalidFrame
  case sequenceMismatch
}

/// Ephemeral, authenticated framing for a move between two unlocked phones.
/// The displayed code must be compared on both devices before any archive frame
/// is sent. Multipeer transport encryption is defense in depth only.
struct IdentityMoveChannel {
  enum Role {
    case source
    case destination
  }

  static let maximumPlaintextBytes = 64 * 1024

  private let role: Role
  private let transferID: UUID
  private let privateKey = P256.KeyAgreement.PrivateKey()
  private var sendKey: SymmetricKey?
  private var receiveKey: SymmetricKey?
  private var sentSequence: UInt64 = 0
  private var receivedSequence: UInt64 = 0

  var publicKey: Data { privateKey.publicKey.x963Representation }

  init(role: Role, transferID: UUID) {
    self.role = role
    self.transferID = transferID
  }

  mutating func establish(peerPublicKey: Data) throws -> String {
    guard sendKey == nil,
      let peer = try? P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
    else { throw IdentityMoveChannelError.invalidPeerKey }
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peer)
    let orderedKeys = [publicKey, peerPublicKey].sorted { $0.lexicographicallyPrecedes($1) }
    var transcript = Data("pigeon.identity-move.handshake.v1".utf8)
    transcript.append(Data(transferID.uuidString.lowercased().utf8))
    for key in orderedKeys { transcript.append(key) }
    let sharedKey = sharedSecret.hkdfDerivedSymmetricKey(
      using: SHA256.self, salt: Data(SHA256.hash(data: transcript)),
      sharedInfo: Data("pigeon.identity-move.master.v1".utf8), outputByteCount: 32)
    let sourceKey = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: sharedKey, salt: Data(),
      info: Data("pigeon.identity-move.source-to-destination.v1".utf8),
      outputByteCount: 32)
    let destinationKey = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: sharedKey, salt: Data(),
      info: Data("pigeon.identity-move.destination-to-source.v1".utf8),
      outputByteCount: 32)
    switch role {
    case .source:
      sendKey = sourceKey
      receiveKey = destinationKey
    case .destination:
      sendKey = destinationKey
      receiveKey = sourceKey
    }
    let digest = HMAC<SHA256>.authenticationCode(
      for: Data("pigeon.identity-move.display-code.v1".utf8) + transcript,
      using: sharedKey)
    let number =
      digest.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
      % 1_000_000_000_000
    return String(format: "%012llu", number)
  }

  mutating func seal(_ plaintext: Data) throws -> Data {
    guard let sendKey, plaintext.count <= Self.maximumPlaintextBytes,
      sentSequence < UInt64.max
    else { throw IdentityMoveChannelError.unavailable }
    let sequence = sentSequence
    let sealed = try AES.GCM.seal(
      plaintext, using: sendKey,
      authenticating: associatedData(sequence: sequence, outbound: true))
    guard let combined = sealed.combined else { throw IdentityMoveChannelError.invalidFrame }
    sentSequence += 1
    return Data([1]) + sequenceBytes(sequence) + combined
  }

  mutating func open(_ frame: Data) throws -> Data {
    guard let receiveKey, frame.count >= 9 + 12 + 16,
      frame.first == 1
    else { throw IdentityMoveChannelError.invalidFrame }
    let sequence = frame.dropFirst().prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    guard sequence == receivedSequence else { throw IdentityMoveChannelError.sequenceMismatch }
    let box = try AES.GCM.SealedBox(combined: Data(frame.dropFirst(9)))
    let plaintext = try AES.GCM.open(
      box, using: receiveKey,
      authenticating: associatedData(sequence: sequence, outbound: false))
    guard plaintext.count <= Self.maximumPlaintextBytes else {
      throw IdentityMoveChannelError.invalidFrame
    }
    receivedSequence += 1
    return plaintext
  }

  private func associatedData(sequence: UInt64, outbound: Bool) -> Data {
    let sourceDirection = outbound ? role == .source : role == .destination
    return Data("pigeon.identity-move.frame.v1".utf8)
      + Data(transferID.uuidString.lowercased().utf8)
      + Data([sourceDirection ? 1 : 2])
      + sequenceBytes(sequence)
  }

  private func sequenceBytes(_ sequence: UInt64) -> Data {
    var bigEndian = sequence.bigEndian
    return withUnsafeBytes(of: &bigEndian) { Data($0) }
  }
}
