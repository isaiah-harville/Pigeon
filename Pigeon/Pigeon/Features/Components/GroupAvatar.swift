import SwiftUI

/// A stable group avatar using the same identity-derived color treatment as
/// contacts and Pigeon's bird silhouette instead of personal initials.
struct GroupAvatar: View {
  let seed: Data
  var size: CGFloat = 52

  var body: some View {
    Circle()
      .fill(
        LinearGradient(
          colors: gradient,
          startPoint: .topLeading,
          endPoint: .bottomTrailing)
      )
      .frame(width: size, height: size)
      .overlay {
        Image(systemName: "bird.fill")
          .font(.system(size: size * 0.45, weight: .semibold))
          .foregroundStyle(.white)
          .accessibilityHidden(true)
      }
      .shadow(color: .black.opacity(0.12), radius: 3, y: 1)
  }

  private var gradient: [Color] {
    let hue = Double(seed.first ?? 0) / 255.0
    return [
      Color(hue: hue, saturation: 0.55, brightness: 0.92),
      Color(hue: hue, saturation: 0.78, brightness: 0.66),
    ]
  }
}
