//
//  RelaySettingsTests.swift
//  PigeonTests
//
//  The relay list model: the recommended relay is always present, only enabled
//  relays are advertised/used, and endpoint validation.
//

import XCTest

@testable import Pigeon

@MainActor
final class RelaySettingsTests: XCTestCase {

  // RelaySettings reads/writes UserDefaults.standard; clear our keys around each test.
  private let keys = ["pigeon.relay.urls", "pigeon.relay.disabled"]

  override func setUp() {
    super.setUp()
    keys.forEach { UserDefaults.standard.removeObject(forKey: $0) }
  }
  override func tearDown() {
    keys.forEach { UserDefaults.standard.removeObject(forKey: $0) }
    super.tearDown()
  }

  func testRecommendedRelayIsAlwaysPresentAndEnabledByDefault() {
    let entries = RelaySettings.entries()
    let recommended = entries.first { $0.url == RelaySettings.recommendedURL }
    XCTAssertNotNil(recommended)
    XCTAssertTrue(recommended?.enabled ?? false)
    XCTAssertEqual(RelaySettings.urls(), [RelaySettings.recommendedURL])
  }

  func testRecommendedRelayReappearsEvenIfNotStored() {
    let custom = URL(string: "wss://custom.example/ws")!
    RelaySettings.setEntries([RelayEntry(url: custom, enabled: true)])
    // The recommended relay is injected back even though we only stored a custom one.
    XCTAssertTrue(RelaySettings.entries().contains { $0.url == RelaySettings.recommendedURL })
  }

  func testOnlyEnabledRelaysAreAdvertised() {
    let custom = URL(string: "wss://custom.example/ws")!
    RelaySettings.setEntries([
      RelayEntry(url: RelaySettings.recommendedURL, enabled: false),
      RelayEntry(url: custom, enabled: true),
    ])
    XCTAssertEqual(RelaySettings.urls(), [custom])  // disabled recommended is excluded
  }

  func testDisablingEverythingAdvertisesNothing() {
    RelaySettings.setEntries([RelayEntry(url: RelaySettings.recommendedURL, enabled: false)])
    XCTAssertTrue(RelaySettings.urls().isEmpty)
  }

  func testEndpointValidation() {
    XCTAssertTrue(RelaySettings.isValidEndpoint("wss://relay.example/ws"))
    XCTAssertTrue(RelaySettings.isValidEndpoint("ws://relay.example/ws"))
    XCTAssertFalse(RelaySettings.isValidEndpoint("https://relay.example"))  // wrong scheme
    XCTAssertFalse(RelaySettings.isValidEndpoint("wss://"))  // no host
    XCTAssertFalse(RelaySettings.isValidEndpoint("garbage"))
  }
}
