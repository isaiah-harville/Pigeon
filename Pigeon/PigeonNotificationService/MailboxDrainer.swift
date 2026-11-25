//
//  MailboxDrainer.swift
//  PigeonNotificationService
//
//  Moves pending relay envelopes into the device spool while the app is not
//  running. For each receiving relay: negotiate the mailbox protocol, prove
//  ownership by signing the relay's challenge with the identity key (the
//  mailbox address), then for every envelope delivered: spool it durably,
//  and only then ack it so the relay deletes its copy.
//
//  It never decrypts, never advances a ratchet, and never registers push
//  tokens. Any failure simply leaves envelopes on the relay for the app.
//

import CryptoKit
import Foundation
import Security

nonisolated struct MailboxDrainer: Sendable {
  /// Relay frames the extension understands; anything else is ignored.
  private static let minimumProtocolVersion = 2
  private static let maximumProtocolVersion = 2
  /// Stop once the relay has been quiet this long after the backlog flush.
  private static let quietPeriod: Duration = .milliseconds(1_500)

  let spool: MailboxSpool
  let config: SharedMailboxConfig.Snapshot
  let signingKey: Curve25519.Signing.PrivateKey

  /// Returns how many envelopes moved into the spool.
  func drain(until deadline: ContinuousClock.Instant) async -> Int {
    await withTaskGroup(of: Int.self) { group in
      for relay in config.relayURLs {
        group.addTask { (try? await drain(relay, until: deadline)) ?? 0 }
      }
      return await group.reduce(0, +)
    }
  }

  private func drain(_ relay: URL, until deadline: ContinuousClock.Instant) async throws -> Int {
    let socket = URLSession.shared.webSocketTask(with: relay)
    socket.resume()
    defer { socket.cancel(with: .goingAway, reason: nil) }

    try await send(
      [
        "type": "hello",
        "min_protocol_version": Self.minimumProtocolVersion,
        "max_protocol_version": Self.maximumProtocolVersion,
      ], over: socket)
    guard try await receive(from: socket, until: deadline)?["type"] as? String == "compatible"
    else { return 0 }

    try await send(["type": "subscribe", "mailbox": config.mailboxHex], over: socket)
    guard let challenge = try await receive(from: socket, until: deadline),
      challenge["type"] as? String == "challenge",
      let nonceText = challenge["nonce"] as? String,
      let nonce = Data(base64Encoded: nonceText)
    else { return 0 }
    let signature = try signingKey.signature(for: nonce)
    try await send(["type": "auth", "signature": signature.base64EncodedString()], over: socket)
    guard try await receive(from: socket, until: deadline)?["type"] as? String == "ok" else {
      return 0
    }

    var spooled = 0
    while ContinuousClock.now < deadline {
      let quietDeadline = min(deadline, ContinuousClock.now + Self.quietPeriod)
      guard let frame = try await receive(from: socket, until: quietDeadline) else { break }
      guard frame["type"] as? String == "envelope",
        let id = frame["id"] as? String,
        let text = frame["ciphertext"] as? String,
        let ciphertext = Data(base64Encoded: text)
      else { continue }
      do {
        try spool.store(ciphertext)
      } catch {
        // Spool full or unwritable: leave this and everything after it on
        // the relay rather than ack something the device does not hold.
        break
      }
      try await send(["type": "ack", "id": id], over: socket)
      spooled += 1
    }
    return spooled
  }

  private func send(_ object: [String: Any], over socket: URLSessionWebSocketTask) async throws {
    let data = try JSONSerialization.data(withJSONObject: object)
    try await socket.send(.string(String(decoding: data, as: UTF8.self)))
  }

  /// The next JSON frame, or `nil` if none arrives before `deadline`. A
  /// timeout closes the socket: `receive()` ignores task cancellation, so
  /// closing is the only way to unblock it, and the caller is finished with
  /// this relay once a deadline passes.
  private func receive(
    from socket: URLSessionWebSocketTask, until deadline: ContinuousClock.Instant
  ) async throws -> [String: Any]? {
    try await withThrowingTaskGroup(of: [String: Any]?.self) { group in
      group.addTask {
        let message = try await socket.receive()
        let data: Data
        switch message {
        case .string(let text): data = Data(text.utf8)
        case .data(let bytes): data = bytes
        @unknown default: return nil
        }
        return try JSONSerialization.jsonObject(with: data) as? [String: Any]
      }
      group.addTask {
        try? await Task.sleep(until: deadline, clock: .continuous)
        if !Task.isCancelled { socket.cancel(with: .goingAway, reason: nil) }
        return nil
      }
      defer { group.cancelAll() }
      guard let first = try await group.next() else { return nil }
      return first
    }
  }
}

nonisolated enum SharedIdentityKey {
  /// Reads the root identity seed from the shared Keychain group. Fails while
  /// the device is locked if the user turned Background Delivery off, since
  /// the seed is then stored `whenUnlocked`.
  static func load() -> Curve25519.Signing.PrivateKey? {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: SharedMailboxConfig.keychainService,
      kSecAttrAccount as String: SharedMailboxConfig.identityAccount,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    if let group = Bundle.main.object(
      forInfoDictionaryKey: SharedMailboxConfig.keychainAccessGroupInfoKey) as? String,
      !group.isEmpty, !group.hasPrefix("$(")
    {
      query[kSecAttrAccessGroup as String] = group
    }
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
      let seed = result as? Data, seed.count == 32
    else { return nil }
    return try? Curve25519.Signing.PrivateKey(rawRepresentation: seed)
  }
}
