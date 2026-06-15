//
//  ContactAvatar.swift
//  Pigeon
//
//  A circular monogram avatar. The gradient is derived deterministically from
//  the contact's identity bytes, so every peer gets a stable, distinct color
//  without storing any extra state.
//

import SwiftUI

struct ContactAvatar: View {
  let name: String
  /// Identity bytes used to pick a stable color. Not displayed.
  let seed: Data
  var size: CGFloat = 52

  var body: some View {
    Circle()
      .fill(
        LinearGradient(
          colors: gradient,
          startPoint: .topLeading,
          endPoint: .bottomTrailing
        )
      )
      .frame(width: size, height: size)
      .overlay {
        Text(initials)
          .font(.system(size: size * 0.4, weight: .semibold, design: .rounded))
          .foregroundStyle(.white)
      }
      .shadow(color: .black.opacity(0.12), radius: 3, y: 1)
  }

  private var initials: String {
    let parts = name.split(separator: " ").prefix(2)
    let letters = parts.compactMap(\.first).map(String.init).joined()
    return letters.isEmpty ? "?" : letters.uppercased()
  }

  private var gradient: [Color] {
    let hue = Double(seed.first ?? 0) / 255.0
    return [
      Color(hue: hue, saturation: 0.55, brightness: 0.92),
      Color(hue: hue, saturation: 0.78, brightness: 0.66),
    ]
  }
}
