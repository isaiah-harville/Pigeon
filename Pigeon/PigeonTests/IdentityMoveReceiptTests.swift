import CryptoKit
import XCTest

@testable import Pigeon

final class IdentityMoveReceiptTests: XCTestCase {
  func testRetirementReceiptBindsTransferAndArchiveDigest() throws {
    let oldIdentity = Curve25519.Signing.PrivateKey()
    let transferID = UUID()
    let digest = Data(SHA256.hash(data: Data("staged archive".utf8)))
    let message = IdentityMoveStage.retirementMessage(
      transferID: transferID, digest: digest)
    let signature = try oldIdentity.signature(for: message)

    XCTAssertTrue(oldIdentity.publicKey.isValidSignature(signature, for: message))
    XCTAssertFalse(
      oldIdentity.publicKey.isValidSignature(
        signature,
        for: IdentityMoveStage.retirementMessage(
          transferID: UUID(), digest: digest)))
    XCTAssertFalse(
      oldIdentity.publicKey.isValidSignature(
        signature,
        for: IdentityMoveStage.retirementMessage(
          transferID: transferID, digest: Data(repeating: 0, count: 32))))
  }
}
