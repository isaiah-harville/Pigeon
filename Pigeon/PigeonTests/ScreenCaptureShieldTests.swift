import UIKit
import XCTest

@testable import Pigeon

@MainActor
final class ScreenCaptureShieldTests: XCTestCase {
  func testCaptureStateViewReportsAttachedSceneState() throws {
    let view = CaptureStateView()
    let scene = try XCTUnwrap(UIApplication.shared.connectedScenes.first as? UIWindowScene)
    let window = UIWindow(windowScene: scene)
    var observed: Bool?
    view.onChange = { observed = $0 }
    window.addSubview(view)

    XCTAssertEqual(observed, view.traitCollection.sceneCaptureState == .active)
  }
}
