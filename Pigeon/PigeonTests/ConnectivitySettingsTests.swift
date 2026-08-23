//
//  ConnectivitySettingsTests.swift
//  PigeonTests
//

import Foundation
import XCTest

@testable import Pigeon

final class ConnectivitySettingsTests: XCTestCase {

  func testConnectivityDefaultsOnAndPersistsFaradayChoice() throws {
    let suite = "ConnectivitySettingsTests-\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }

    XCTAssertTrue(ConnectivitySettings.isEnabled(in: defaults))

    ConnectivitySettings.setEnabled(false, in: defaults)

    XCTAssertFalse(ConnectivitySettings.isEnabled(in: defaults))
  }

  func testTransportGatePublishesFinalStateAcrossConcurrentAccess() {
    let gate = TransportGate(enabled: true)
    let work = DispatchGroup()
    let queue = DispatchQueue(label: "TransportGateTests", attributes: .concurrent)

    for index in 0..<1_000 {
      work.enter()
      queue.async {
        gate.setEnabled(index.isMultiple(of: 2))
        _ = gate.isEnabled
        work.leave()
      }
    }
    work.wait()
    gate.setEnabled(false)

    XCTAssertFalse(gate.isEnabled)
  }

  func testTransportGateFinishesAuthorizedActionBeforeDisableReturns() {
    let gate = TransportGate(enabled: true)
    let actionStarted = DispatchSemaphore(value: 0)
    let releaseAction = DispatchSemaphore(value: 0)
    let disableReturned = DispatchSemaphore(value: 0)
    let queue = DispatchQueue(label: "TransportGateOrderingTests", attributes: .concurrent)

    queue.async {
      gate.performIfEnabled {
        actionStarted.signal()
        releaseAction.wait()
      }
    }
    XCTAssertEqual(actionStarted.wait(timeout: .now() + 1), .success)

    queue.async {
      gate.setEnabled(false)
      disableReturned.signal()
    }

    XCTAssertEqual(disableReturned.wait(timeout: .now() + 0.05), .timedOut)
    releaseAction.signal()
    XCTAssertEqual(disableReturned.wait(timeout: .now() + 1), .success)
    XCTAssertFalse(gate.isEnabled)
  }
}
