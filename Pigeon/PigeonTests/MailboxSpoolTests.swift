import Foundation
import XCTest

@testable import Pigeon

final class MailboxSpoolTests: XCTestCase {
  private var directory: URL!

  override func setUpWithError() throws {
    directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("spool-\(UUID().uuidString)", isDirectory: true)
  }

  override func tearDownWithError() throws {
    try? FileManager.default.removeItem(at: directory)
  }

  func testEntriesDrainInArrivalOrderAndDuplicatesCollapse() throws {
    let spool = MailboxSpool(directory: directory)
    try spool.store(Data([2]), receivedAt: Date(timeIntervalSince1970: 20))
    try spool.store(Data([1]), receivedAt: Date(timeIntervalSince1970: 10))
    try spool.store(Data([2]), receivedAt: Date(timeIntervalSince1970: 30))

    let entries = try spool.entries()
    XCTAssertEqual(entries.map(\.data), [Data([1]), Data([2])])

    spool.remove(entries[0])
    XCTAssertEqual(try spool.entries().map(\.data), [Data([2])])
  }

  func testSpoolRefusesEmptyOversizedAndOverflowingWrites() throws {
    let spool = MailboxSpool(directory: directory)
    XCTAssertThrowsError(try spool.store(Data()))
    XCTAssertThrowsError(try spool.store(Data(count: MailboxSpool.maximumEntryBytes + 1)))
    XCTAssertTrue(try spool.entries().isEmpty)
  }

  /// The extension acks the relay only after `store` returns, so a stored
  /// entry must already be a complete, named file with no temp leftovers.
  func testStoredEntryIsCompleteBeforeStoreReturns() throws {
    let spool = MailboxSpool(directory: directory)
    let payload = Data((0..<4096).map { UInt8($0 % 251) })
    try spool.store(payload)
    let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
    XCTAssertEqual(names.count, 1)
    XCTAssertTrue(names[0].hasSuffix(".envelope"))
    XCTAssertEqual(try spool.entries().first?.data, payload)
  }
}
