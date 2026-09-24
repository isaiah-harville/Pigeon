import CryptoKit
import Foundation
import PigeonFFI
import XCTest

@testable import Pigeon

final class CoreCheckpointStoreTests: XCTestCase {
  private enum WriteFailure: Error {
    case injected
  }

  func testCheckpointRoundTripIsEncryptedAndGenerationChecked() throws {
    let fixture = makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.url) }
    let checkpoint = makeCheckpoint(generation: 1, bytes: Data("secret MLS state".utf8))

    try fixture.store.replace(expectedGeneration: 0, next: checkpoint)

    XCTAssertEqual(try fixture.store.load(), checkpoint)
    XCTAssertFalse(try Data(contentsOf: fixture.url).contains(checkpoint.bytes))
  }

  func testGenerationConflictLeavesCurrentCheckpointUnchanged() throws {
    let fixture = makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.url) }
    let first = makeCheckpoint(generation: 1, bytes: Data("first".utf8))
    let second = makeCheckpoint(generation: 2, bytes: Data("second".utf8))
    try fixture.store.replace(expectedGeneration: 0, next: first)

    XCTAssertThrowsError(
      try fixture.store.replace(expectedGeneration: 0, next: second)
    ) { error in
      XCTAssertEqual(error as? PlatformError, .Conflict)
    }
    XCTAssertEqual(try fixture.store.load(), first)
  }

  func testInvalidChecksumIsRejectedBeforeReplacingCurrentCheckpoint() throws {
    let fixture = makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.url) }
    let first = makeCheckpoint(generation: 1, bytes: Data("first".utf8))
    try fixture.store.replace(expectedGeneration: 0, next: first)
    let invalid = Checkpoint(
      generation: 2,
      bytes: Data("tampered".utf8),
      sha256: Data(repeating: 0, count: 32))

    XCTAssertThrowsError(
      try fixture.store.replace(expectedGeneration: 1, next: invalid)
    ) { error in
      XCTAssertEqual(error as? PlatformError, .InvalidOutput)
    }
    XCTAssertEqual(try fixture.store.load(), first)
  }

  func testFailedAtomicWritePreservesCurrentCheckpoint() throws {
    let url = temporaryURL()
    let key = SymmetricKey(size: .bits256)
    var failWrites = false
    let io = EncryptedStoreIO(
      write: { data, destination, options in
        if failWrites { throw WriteFailure.injected }
        try data.write(to: destination, options: options)
      },
      remove: { try FileManager.default.removeItem(at: $0) })
    let encryptedStore = EncryptedStore(key: key, url: url, io: io)
    let store = CoreCheckpointStore(store: encryptedStore)
    defer { try? FileManager.default.removeItem(at: url) }
    let first = makeCheckpoint(generation: 1, bytes: Data("first".utf8))
    try store.replace(expectedGeneration: 0, next: first)

    failWrites = true
    XCTAssertThrowsError(
      try store.replace(
        expectedGeneration: 1,
        next: makeCheckpoint(generation: 2, bytes: Data("second".utf8)))
    ) { error in
      XCTAssertEqual(error as? PlatformError, .Unavailable)
    }
    failWrites = false
    XCTAssertEqual(try store.load(), first)
  }

  func testCorruptStoredChecksumIsNotLoaded() throws {
    let fixture = makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.url) }
    XCTAssertTrue(
      fixture.encryptedStore.save(
        PersistedCoreCheckpoint(
          generation: 1,
          bytes: Data("tampered".utf8),
          sha256: Data(repeating: 0, count: 32))))

    XCTAssertThrowsError(try fixture.store.load()) { error in
      XCTAssertEqual(error as? PlatformError, .Corrupt)
    }
  }

  private func makeCheckpoint(generation: UInt64, bytes: Data) -> Checkpoint {
    Checkpoint(
      generation: generation,
      bytes: bytes,
      sha256: Data(SHA256.hash(data: bytes)))
  }

  private func makeFixture() -> (
    store: CoreCheckpointStore, encryptedStore: EncryptedStore, url: URL
  ) {
    let url = temporaryURL()
    let encryptedStore = EncryptedStore(key: SymmetricKey(size: .bits256), url: url)
    return (CoreCheckpointStore(store: encryptedStore), encryptedStore, url)
  }

  private func temporaryURL() -> URL {
    FileManager.default.temporaryDirectory
      .appendingPathComponent("pigeon-core-checkpoint-\(UUID().uuidString).store")
  }
}
