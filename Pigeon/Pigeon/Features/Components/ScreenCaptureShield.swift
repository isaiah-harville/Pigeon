//
//  ScreenCaptureShield.swift
//  Pigeon
//
//  Hides sensitive UI during recording and external capture using supported
//  UIKit capture-state APIs. Still screenshots are reported only after capture.
//

import SwiftUI

#if os(iOS)
  import UIKit

  struct ScreenCaptureShield: ViewModifier {
    // Wait for the attached scene's capture state before showing sensitive content.
    @State private var isCaptured = true

    func body(content: Content) -> some View {
      content
        .background(CaptureStateObserver(isCaptured: $isCaptured))
        .overlay {
          if isCaptured {
            ZStack {
              Color.black.ignoresSafeArea()
              Label("Screen capture hidden", systemImage: "eye.slash.fill")
                .foregroundStyle(.white)
            }
          }
        }
    }
  }

  private struct CaptureStateObserver: UIViewRepresentable {
    @Binding var isCaptured: Bool

    func makeUIView(context: Context) -> CaptureStateView {
      let view = CaptureStateView()
      updateUIView(view, context: context)
      return view
    }

    func updateUIView(_ view: CaptureStateView, context _: Context) {
      view.onChange = { captured in
        Task { @MainActor in isCaptured = captured }
      }
    }
  }

  final class CaptureStateView: UIView {
    var onChange: ((Bool) -> Void)?

    override init(frame: CGRect) {
      super.init(frame: frame)
      registerForTraitChanges([UITraitSceneCaptureState.self]) { (view: CaptureStateView, _) in
        view.reportCaptureState()
      }
    }

    required init?(coder _: NSCoder) { nil }

    override func didMoveToWindow() {
      super.didMoveToWindow()
      reportCaptureState()
    }

    private func reportCaptureState() {
      onChange?(traitCollection.sceneCaptureState == .active)
    }
  }

  extension View {
    func screenCaptureShield() -> some View {
      modifier(ScreenCaptureShield())
    }
  }
#else
  extension View {
    func screenCaptureShield() -> some View { self }
  }
#endif
