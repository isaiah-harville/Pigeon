//
//  SessionManager+PairwiseInbound.swift
//  Pigeon
//

import Foundation
import PigeonFFI

extension SessionManager {
  func consumePairwiseMessage(_ ciphertext: Data, requestID: String)
    -> TransportMessageDisposition
  {
    guard isUnlocked, isPersistenceHealthy else { return .retryAfterRestart }
    do {
      try executeCore(
        PigeonCoreCommand(
          id: "pairwise-message:\(requestID)",
          body: .applyInbound(
            PigeonApplyInbound(
              kind: .pairwise,
              payload: ciphertext,
              requestID: requestID))))
      return .consumed
    } catch {
      return TransportMessageDisposition(pairwiseFailure: error)
    }
  }
}

extension TransportMessageDisposition {
  /// Decides whether a pairwise message the core refused may be deleted from
  /// the relay.
  ///
  /// A failure about the message itself (bad signature, malformed bytes, a
  /// replay, an unknown sender without a card, a full request inbox) gives the
  /// same answer on every redelivery, so the copy is consumed. Retrying it
  /// would keep it in the mailbox until it expires, and anyone holding our
  /// public key could fill the mailbox's queue that way and lock out real mail.
  /// The core rejects these before any state changes, so consuming loses
  /// nothing but the message.
  ///
  /// A failure of this device (storage, the platform signer, local state that
  /// will not decode) can clear, so the copy stays for a clean retry.
  init(pairwiseFailure error: any Error) {
    switch error as? PigeonError {
    case .InvalidKey, .InvalidSignature, .MalformedBundle, .NotAPreKeyMessage,
      .SessionCreation, .Decryption, .ResourceLimit, .UnsupportedVersion:
      self = .consumed
    case .Entropy, .Encryption, .Serialization, .Persistence, .Identity,
      .GroupPolicy, .Mls, nil:
      self = .retryAfterRestart
    }
  }
}
