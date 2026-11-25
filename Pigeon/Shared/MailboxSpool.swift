//
//  MailboxSpool.swift
//  Pigeon (shared with PigeonNotificationService)
//
//  A durable, device-local spool for relay envelopes collected while the app
//  is not running — typically by the notification service extension while the
//  phone is locked.
//
//  Custody model ("spool and ack"): the extension writes each envelope here
//  and fsyncs it *before* acking the relay, so the device, not the relay, holds
//  the only copy from then on. Entries are the relay's opaque ciphertext
//  exactly as received (a mesh packet around a pairwise session envelope); the
//  extension never decrypts and never touches the Olm ratchet. The app drains
//  the spool through the same inbound path as live relay delivery once the
//  vault is unlocked, and deletes an entry only after the core has durably
//  consumed it.
//
//  Files use `completeUntilFirstUserAuthentication` so a locked device can
//  write them. That is no new exposure: the bytes are end-to-end ciphertext
//  the relay already held, and confidentiality still rests on the sealed Olm
//  state behind the presence-gated vault key.
//

import CryptoKit
import Foundation

nonisolated struct MailboxSpool: Sendable {
  struct Entry: Equatable, Sendable {
    let url: URL
    let data: Data
  }

  enum SpoolError: Error, Equatable {
    case full
    case writeFailed
  }

  /// Bounds so a flood of deposits cannot exhaust the device. Past either
  /// bound the extension stops acking and the relay keeps the rest.
  static let maximumEntries = 2_000
  static let maximumBytes = 64 * 1024 * 1024
  static let maximumEntryBytes = 512 * 1024

  private static let fileExtension = "envelope"

  let directory: URL

  init(directory: URL) {
    self.directory = directory
  }

  /// The shared spool in the app-group container, or `nil` when the
  /// entitlement is unavailable (for example, an unsigned build).
  static var shared: MailboxSpool? {
    guard
      let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: SharedMailboxConfig.appGroup)
    else { return nil }
    return MailboxSpool(
      directory: container.appendingPathComponent("MailboxSpool", isDirectory: true))
  }

  /// Durably stores one envelope. Returns only after the bytes and the
  /// directory entry are on stable storage, so acking the relay afterwards
  /// can never lose the message. Writing the same envelope twice keeps one
  /// file (the name is derived from the bytes).
  func store(_ data: Data, receivedAt date: Date = Date()) throws {
    guard !data.isEmpty, data.count <= Self.maximumEntryBytes else { throw SpoolError.writeFailed }
    try prepareDirectory()
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let existing = try entryURLs()
    if existing.contains(where: {
      $0.lastPathComponent.hasSuffix("-\(digest).\(Self.fileExtension)")
    }) {
      return
    }
    let bytes = try existing.reduce(0) { total, url in
      total + ((try url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
    }
    guard existing.count < Self.maximumEntries, bytes + data.count <= Self.maximumBytes else {
      throw SpoolError.full
    }
    // Millisecond prefix keeps drain order close to arrival order.
    let stamp = String(format: "%015llu", UInt64(max(0, date.timeIntervalSince1970 * 1_000)))
    let target = directory.appendingPathComponent("\(stamp)-\(digest).\(Self.fileExtension)")
    let temporary = directory.appendingPathComponent(".\(UUID().uuidString).tmp")
    guard
      FileManager.default.createFile(
        atPath: temporary.path, contents: nil,
        attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
    else { throw SpoolError.writeFailed }
    do {
      let handle = try FileHandle(forWritingTo: temporary)
      defer { try? handle.close() }
      try handle.write(contentsOf: data)
      try handle.synchronize()
    } catch {
      try? FileManager.default.removeItem(at: temporary)
      throw SpoolError.writeFailed
    }
    guard rename(temporary.path, target.path) == 0 else {
      try? FileManager.default.removeItem(at: temporary)
      throw SpoolError.writeFailed
    }
    try synchronizeDirectory()
  }

  /// Every spooled envelope, oldest first. Unreadable files are skipped and
  /// left for a later drain.
  func entries() throws -> [Entry] {
    try entryURLs().compactMap { url in
      (try? Data(contentsOf: url)).map { Entry(url: url, data: $0) }
    }
  }

  /// Deletes an entry once the app has durably consumed it.
  func remove(_ entry: Entry) {
    try? FileManager.default.removeItem(at: entry.url)
  }

  private func entryURLs() throws -> [URL] {
    guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
    return try FileManager.default
      .contentsOfDirectory(at: directory, includingPropertiesForKeys: [.fileSizeKey])
      .filter { $0.pathExtension == Self.fileExtension }
      .sorted { $0.lastPathComponent < $1.lastPathComponent }
  }

  private func prepareDirectory() throws {
    guard !FileManager.default.fileExists(atPath: directory.path) else { return }
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
  }

  private func synchronizeDirectory() throws {
    let descriptor = open(directory.path, O_RDONLY)
    guard descriptor >= 0 else { throw SpoolError.writeFailed }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw SpoolError.writeFailed }
  }
}
