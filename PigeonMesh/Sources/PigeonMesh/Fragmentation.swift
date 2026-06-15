//
//  Fragmentation.swift
//  PigeonMesh
//
//  Splits logical messages into BLE-sized fragments and reassembles them.
//
//  Bluetooth LE delivers small payloads (the usable ATT MTU is often
//  ~180–500 bytes), so any message larger than one fragment must be chopped
//  up on send and stitched back together on receive — tolerating fragments
//  that arrive out of order or duplicated.
//

import Foundation

public enum FragmentationError: Error, Equatable {
  /// A fragment's bytes were malformed or too short to decode.
  case malformedFragment
  /// A fragment's index/count fields are inconsistent (e.g. index >= count).
  case inconsistentFragment
  /// The message exceeds the configured reassembly size limit.
  case messageTooLarge
  /// The message needs more fragments than the wire format can address.
  case tooManyFragments
}

/// One BLE-sized piece of a logical message.
///
/// Wire layout (7-byte header, big-endian): `version(1) ‖ messageID(2) ‖
/// index(2) ‖ count(2) ‖ payload`. The header is small enough to leave most
/// of a minimal BLE MTU for payload.
public struct Fragment: Equatable, Sendable {
  public static let headerSize = 7
  public static let version: UInt8 = 1

  /// Identifies the logical message this fragment belongs to (per link,
  /// wraps at 2^16).
  public let messageID: UInt16
  /// Zero-based position of this fragment within the message.
  public let index: UInt16
  /// Total number of fragments in the message.
  public let count: UInt16
  public let payload: Data

  public init(messageID: UInt16, index: UInt16, count: UInt16, payload: Data) {
    self.messageID = messageID
    self.index = index
    self.count = count
    self.payload = payload
  }

  public func encoded() -> Data {
    var data = Data(capacity: Self.headerSize + payload.count)
    data.append(Self.version)
    data.append(contentsOf: withUnsafeBytes(of: messageID.bigEndian, Array.init))
    data.append(contentsOf: withUnsafeBytes(of: index.bigEndian, Array.init))
    data.append(contentsOf: withUnsafeBytes(of: count.bigEndian, Array.init))
    data.append(payload)
    return data
  }

  public init(decoding data: Data) throws {
    guard data.count >= Self.headerSize else { throw FragmentationError.malformedFragment }
    let base = data.startIndex
    guard data[base] == Self.version else { throw FragmentationError.malformedFragment }
    self.messageID = data.readBigEndianUInt16(at: base + 1)
    self.index = data.readBigEndianUInt16(at: base + 3)
    self.count = data.readBigEndianUInt16(at: base + 5)
    self.payload = Data(data[(base + Self.headerSize)...])
    guard count >= 1, index < count else { throw FragmentationError.inconsistentFragment }
  }
}

/// Splits outbound messages into ordered fragments, assigning each message a
/// rolling identifier so the peer can group its fragments.
public struct Fragmenter {
  private var nextMessageID: UInt16

  public init(initialMessageID: UInt16 = 0) {
    self.nextMessageID = initialMessageID
  }

  /// Fragments `message` so each fragment's payload is at most
  /// `maxPayloadPerFragment` bytes. `maxPayloadPerFragment` should be the
  /// negotiated usable MTU minus `Fragment.headerSize`.
  public mutating func fragment(_ message: Data, maxPayloadPerFragment: Int) throws -> [Fragment] {
    precondition(maxPayloadPerFragment > 0, "fragment payload size must be positive")

    let id = nextMessageID
    nextMessageID = nextMessageID &+ 1

    // Even an empty message is one (empty) fragment, so it is delivered.
    let chunkCount = max(
      1, Int((message.count + maxPayloadPerFragment - 1) / maxPayloadPerFragment))
    guard chunkCount <= Int(UInt16.max) else { throw FragmentationError.tooManyFragments }

    var fragments: [Fragment] = []
    fragments.reserveCapacity(chunkCount)
    var offset = message.startIndex
    for i in 0..<chunkCount {
      let end =
        message.index(offset, offsetBy: maxPayloadPerFragment, limitedBy: message.endIndex)
        ?? message.endIndex
      fragments.append(
        Fragment(
          messageID: id,
          index: UInt16(i),
          count: UInt16(chunkCount),
          payload: Data(message[offset..<end])))
      offset = end
    }
    return fragments
  }
}

/// Reassembles fragments into whole messages, tolerating reordering and
/// duplicates, with bounds to resist memory exhaustion from malicious or lost
/// fragment streams.
public final class Reassembler {

  private struct Pending {
    let count: UInt16
    var fragments: [UInt16: Data]
    var byteCount: Int
    var sequence: UInt64  // for oldest-first eviction
  }

  private let maxMessageBytes: Int
  private let maxConcurrentMessages: Int
  private var pending: [UInt16: Pending] = [:]
  private var sequenceCounter: UInt64 = 0

  public init(maxMessageBytes: Int = 256 * 1024, maxConcurrentMessages: Int = 64) {
    self.maxMessageBytes = maxMessageBytes
    self.maxConcurrentMessages = maxConcurrentMessages
  }

  /// Feeds one fragment in. Returns the complete message once its final
  /// missing fragment arrives, otherwise `nil`.
  public func ingest(_ fragment: Fragment) throws -> Data? {
    guard fragment.count >= 1, fragment.index < fragment.count else {
      throw FragmentationError.inconsistentFragment
    }

    // Single-fragment fast path: nothing to buffer.
    if fragment.count == 1 {
      pending[fragment.messageID] = nil
      guard fragment.payload.count <= maxMessageBytes else {
        throw FragmentationError.messageTooLarge
      }
      return fragment.payload
    }

    sequenceCounter &+= 1

    // Start (or reset, if the count changed — a reused ID) the pending entry.
    var entry: Pending
    if let existing = pending[fragment.messageID], existing.count == fragment.count {
      entry = existing
    } else {
      entry = Pending(
        count: fragment.count, fragments: [:], byteCount: 0, sequence: sequenceCounter)
    }

    // Ignore duplicate fragments rather than double-counting bytes.
    if entry.fragments[fragment.index] == nil {
      entry.byteCount += fragment.payload.count
      guard entry.byteCount <= maxMessageBytes else {
        pending[fragment.messageID] = nil
        throw FragmentationError.messageTooLarge
      }
      entry.fragments[fragment.index] = fragment.payload
    }

    // Complete?
    if entry.fragments.count == Int(entry.count) {
      pending[fragment.messageID] = nil
      var message = Data(capacity: entry.byteCount)
      for i in 0..<entry.count {
        guard let part = entry.fragments[i] else { throw FragmentationError.inconsistentFragment }
        message.append(part)
      }
      return message
    }

    pending[fragment.messageID] = entry
    evictIfNeeded()
    return nil
  }

  /// Number of in-flight (incomplete) messages currently buffered.
  public var pendingCount: Int { pending.count }

  /// Drops the oldest incomplete message(s) once too many accumulate.
  private func evictIfNeeded() {
    guard pending.count > maxConcurrentMessages else { return }
    if let oldest = pending.min(by: { $0.value.sequence < $1.value.sequence })?.key {
      pending[oldest] = nil
    }
  }
}

extension Data {
  fileprivate func readBigEndianUInt16(at index: Int) -> UInt16 {
    (UInt16(self[index]) << 8) | UInt16(self[index + 1])
  }
}
