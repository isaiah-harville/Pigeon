//
//  ScreenCaptureShield.swift
//  Pigeon
//
//  Hides sensitive UI during recording and external capture using supported
//  UIKit capture-state APIs. Still screenshots are reported only after capture.
//

import SwiftUI

#if os(iOS)
  import Combine
  import UIKit

  struct ScreenCaptureShield: ViewModifier {
    @State private var isCaptured = UIScreen.main.isCaptured

    func body(content: Content) -> some View {
      content
        .overlay {
          if isCaptured {
            ZStack {
              Color.black.ignoresSafeArea()
              Label("Screen capture hidden", systemImage: "eye.slash.fill")
                .foregroundStyle(.white)
            }
          }
        }
        .onReceive(
          NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)
        ) { _ in
          isCaptured = UIScreen.main.isCaptured
        }
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
