import XCTest

@testable import Pigeon

final class VaultContinuityTests: XCTestCase {
  func testMissingKeyAfterInitializationCannotStartAnEmptyHistory() {
    XCTAssertNoThrow(try Vault.checkNewKeyCreationAllowed(wasInitialized: false))
    XCTAssertThrowsError(try Vault.checkNewKeyCreationAllowed(wasInitialized: true)) { error in
      guard case VaultError.missingStoredKey = error else {
        XCTFail("Missing existing DEK must be distinct from a first launch")
        return
      }
    }
  }
}
