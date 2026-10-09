import XCTest

@testable import Pigeon

final class IdentityMoveChannelTests: XCTestCase {
  func testPeersDeriveSameCodeAndExchangeAuthenticatedFrames() throws {
    let moveID = UUID()
    var source = IdentityMoveChannel(role: .source, transferID: moveID)
    var destination = IdentityMoveChannel(role: .destination, transferID: moveID)
    let sourceCode = try source.establish(peerPublicKey: destination.publicKey)
    let destinationCode = try destination.establish(peerPublicKey: source.publicKey)
    XCTAssertEqual(sourceCode, destinationCode)
    XCTAssertEqual(sourceCode.count, 12)

    let frame = try source.seal(Data("state".utf8))
    XCTAssertEqual(try destination.open(frame), Data("state".utf8))
    XCTAssertThrowsError(try destination.open(frame))
    let reply = try destination.seal(Data("staged".utf8))
    XCTAssertEqual(try source.open(reply), Data("staged".utf8))
  }

  func testWrongTransferAndTamperedFramesFail() throws {
    var source = IdentityMoveChannel(role: .source, transferID: UUID())
    var destination = IdentityMoveChannel(role: .destination, transferID: UUID())
    _ = try source.establish(peerPublicKey: destination.publicKey)
    _ = try destination.establish(peerPublicKey: source.publicKey)
    var frame = try source.seal(Data("private".utf8))
    XCTAssertThrowsError(try destination.open(frame))
    frame[frame.count - 1] ^= 1
    XCTAssertThrowsError(try destination.open(frame))
  }
}
