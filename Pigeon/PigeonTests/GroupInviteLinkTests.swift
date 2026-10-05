import XCTest

@testable import Pigeon

final class GroupInviteLinkTests: XCTestCase {
  func testTicketStaysInFragmentAndRoundTripsWithoutQueryParameters() throws {
    let ticket = Data((0..<256).map(UInt8.init))
    let url = try XCTUnwrap(GroupInviteLink.url(for: ticket))
    XCTAssertEqual(url.host, "pigeonwire.app")
    XCTAssertEqual(url.path, "/group")
    XCTAssertNil(URLComponents(url: url, resolvingAgainstBaseURL: false)?.query)
    XCTAssertEqual(GroupInviteLink.ticketBytes(from: url.absoluteString), ticket)
  }

  func testRejectsForeignHostsAndTicketInQuery() {
    let ticket = Data([1, 2, 3])
    let url = GroupInviteLink.url(for: ticket)!.absoluteString
    XCTAssertNil(
      GroupInviteLink.ticketBytes(
        from: url.replacingOccurrences(
          of: "pigeonwire.app", with: "attacker.example")))
    XCTAssertNil(GroupInviteLink.ticketBytes(from: "https://pigeonwire.app/group?ticket=AQID"))
    XCTAssertNil(GroupInviteLink.ticketBytes(from: "https://pigeonwire.app/group#ticket=AQID&x=1"))
    XCTAssertNil(GroupInviteLink.ticketBytes(from: "https://pigeonwire.app/group#ticket=%%%%"))
  }
}
