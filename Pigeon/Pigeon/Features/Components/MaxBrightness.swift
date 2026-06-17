//
//  MaxBrightness.swift
//  Pigeon
//
//  A view modifier that raises screen brightness to maximum while a QR code is
//  on screen (so a peer's camera can scan it reliably), restoring the previous
//  level when it's dismissed or hidden.
//

import SwiftUI
import UIKit

extension View {
  /// Raises screen brightness to full while the view is on screen, restoring the
  /// prior level when it disappears.
  func maxBrightness() -> some View {
    modifier(MaxBrightnessModifier(active: true))
  }

  /// Raises screen brightness to full while `active` is true, restoring the
  /// prior level when it becomes false or the view disappears.
  func maxBrightness(while active: Bool) -> some View {
    modifier(MaxBrightnessModifier(active: active))
  }
}

private struct MaxBrightnessModifier: ViewModifier {
  let active: Bool

  /// The brightness to restore. `nil` means we have not raised it (so restore
  /// is a no-op and we never overwrite a saved value with our own 1.0).
  @State private var priorBrightness: CGFloat?

  func body(content: Content) -> some View {
    content
      .onAppear { if active { raise() } }
      .onChange(of: active) { _, isActive in
        if isActive { raise() } else { restore() }
      }
      .onDisappear { restore() }
  }

  private func raise() {
    guard priorBrightness == nil, let screen = Self.activeScreen else { return }
    priorBrightness = screen.brightness
    screen.brightness = 1.0
  }

  private func restore() {
    guard let prior = priorBrightness else { return }
    Self.activeScreen?.brightness = prior
    priorBrightness = nil
  }

  /// The foreground scene's screen. Uses the per-window-scene screen rather than
  /// the deprecated `UIScreen.main` (iOS 26+).
  private static var activeScreen: UIScreen? {
    UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .first { $0.activationState == .foregroundActive }?
      .screen
  }
}
