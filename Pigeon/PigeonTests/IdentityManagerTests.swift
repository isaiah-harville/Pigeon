import Foundation
import Security
import XCTest

@testable import Pigeon

private final class FakeKeychainClient: KeychainClient {
  var storedData: Data?
  var forcedAddStatus: OSStatus?
  var forcedUpdateStatus: OSStatus?
  var forcedDeleteStatus: OSStatus?
  private(set) var addCount = 0
  private(set) var updateCount = 0
  private(set) var deleteCount = 0

  init(storedData: Data?) {
    self.storedData = storedData
  }

  func copyMatching(_ query: [String: Any]) -> (OSStatus, Data?) {
    guard let storedData else { return (errSecItemNotFound, nil) }
    return (errSecSuccess, storedData)
  }

  func add(_ attributes: [String: Any]) -> OSStatus {
    addCount += 1
    if let forcedAddStatus { return forcedAddStatus }
    guard storedData == nil else { return errSecDuplicateItem }
    storedData = attributes[kSecValueData as String] as? Data
    return storedData == nil ? errSecParam : errSecSuccess
  }

  func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
    updateCount += 1
    if let forcedUpdateStatus { return forcedUpdateStatus }
    guard storedData != nil else { return errSecItemNotFound }
    if let replacement = attributes[kSecValueData as String] as? Data {
      storedData = replacement
    }
    return errSecSuccess
  }

  func delete(_ query: [String: Any]) -> OSStatus {
    deleteCount += 1
    if let forcedDeleteStatus { return forcedDeleteStatus }
    guard storedData != nil else { return errSecItemNotFound }
    storedData = nil
    return errSecSuccess
  }
}

private final class MemoryIdentityInitializationStore: IdentityInitializationStore {
  var wasInitialized: Bool

  init(wasInitialized: Bool) {
    self.wasInitialized = wasInitialized
  }

  func markInitialized() {
    wasInitialized = true
  }
}

private final class MemoryIdentityKeyStore: KeyStore {
  var data: Data?

  init(data: Data?) {
    self.data = data
  }

  func get() throws -> Data? { data }
  func set(_ data: Data, accessibility: KeychainAccessibility) throws { self.data = data }
  func setAccessibility(_ accessibility: KeychainAccessibility) throws {}
  func delete() throws { data = nil }
}

final class IdentityManagerTests: XCTestCase {
  func testReplacementUpdateFailurePreservesExistingIdentityBytes() throws {
    let original = Data(repeating: 1, count: 32)
    let client = FakeKeychainClient(storedData: original)
    client.forcedUpdateStatus = errSecNotAvailable
    let store = KeychainStore(account: "test", client: client)

    XCTAssertThrowsError(
      try store.set(Data(repeating: 2, count: 32), accessibility: .whenUnlocked))
    XCTAssertEqual(client.storedData, original)
    XCTAssertEqual(client.updateCount, 1)
    XCTAssertEqual(client.addCount, 0)
    XCTAssertEqual(client.deleteCount, 0)
  }

  func testMissingIdentityUsesAddWithoutDelete() throws {
    let replacement = Data(repeating: 3, count: 32)
    let client = FakeKeychainClient(storedData: nil)
    let store = KeychainStore(account: "test", client: client)

    try store.set(replacement, accessibility: .afterFirstUnlock)

    XCTAssertEqual(client.storedData, replacement)
    XCTAssertEqual(client.updateCount, 1)
    XCTAssertEqual(client.addCount, 1)
    XCTAssertEqual(client.deleteCount, 0)
  }

  func testAddFailureLeavesIdentityMissingAndThrows() {
    let client = FakeKeychainClient(storedData: nil)
    client.forcedAddStatus = errSecNotAvailable
    let store = KeychainStore(account: "test", client: client)

    XCTAssertThrowsError(
      try store.set(Data(repeating: 4, count: 32), accessibility: .whenUnlocked))
    XCTAssertNil(client.storedData)
  }

  func testAccessibilityUpdateFailurePreservesIdentityBytes() {
    let original = Data(repeating: 5, count: 32)
    let client = FakeKeychainClient(storedData: original)
    client.forcedUpdateStatus = errSecNotAvailable
    let store = KeychainStore(account: "test", client: client)

    XCTAssertThrowsError(try store.setAccessibility(.afterFirstUnlock))
    XCTAssertEqual(client.storedData, original)
    XCTAssertEqual(client.deleteCount, 0)
  }

  func testDeleteFailureIsSurfacedWithoutDiscardingIdentity() {
    let original = Data(repeating: 6, count: 32)
    let client = FakeKeychainClient(storedData: original)
    client.forcedDeleteStatus = errSecNotAvailable
    let store = KeychainStore(account: "test", client: client)

    XCTAssertThrowsError(try store.delete())
    XCTAssertEqual(client.storedData, original)
  }

  func testPreviouslyInitializedInstallDoesNotSilentlyGenerateMissingIdentity() {
    let keyStore = MemoryIdentityKeyStore(data: nil)
    let initialization = MemoryIdentityInitializationStore(wasInitialized: true)

    XCTAssertThrowsError(
      try IdentityManager(store: keyStore, initializationStore: initialization)
    ) { error in
      XCTAssertEqual(error as? IdentityManagerError, .missingStoredIdentity)
    }
    XCTAssertNil(keyStore.data)
  }
}
