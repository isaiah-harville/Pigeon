//
//  ScannerReticle.swift
//  Pigeon
//
//  The four rounded corner brackets drawn over the QR camera preview, framing
//  where to aim. Purely decorative; it does no detection itself.
//

import SwiftUI

/// Strokes four rounded L-shaped brackets, one in each corner of its bounds.
struct ScannerReticleShape: Shape {
  /// Length of each leg of a corner bracket.
  var legLength: CGFloat = 38
  /// Radius of the rounded turn at each corner.
  var radius: CGFloat = 26

  func path(in rect: CGRect) -> Path {
    var path = Path()
    let cornerRadius = min(radius, min(rect.width, rect.height) / 2)
    let leg = legLength

    // Top-left
    path.move(to: CGPoint(x: rect.minX, y: rect.minY + cornerRadius + leg))
    path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + cornerRadius))
    path.addQuadCurve(
      to: CGPoint(x: rect.minX + cornerRadius, y: rect.minY),
      control: CGPoint(x: rect.minX, y: rect.minY))
    path.addLine(to: CGPoint(x: rect.minX + cornerRadius + leg, y: rect.minY))

    // Top-right
    path.move(to: CGPoint(x: rect.maxX - cornerRadius - leg, y: rect.minY))
    path.addLine(to: CGPoint(x: rect.maxX - cornerRadius, y: rect.minY))
    path.addQuadCurve(
      to: CGPoint(x: rect.maxX, y: rect.minY + cornerRadius),
      control: CGPoint(x: rect.maxX, y: rect.minY))
    path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + cornerRadius + leg))

    // Bottom-right
    path.move(to: CGPoint(x: rect.maxX, y: rect.maxY - cornerRadius - leg))
    path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - cornerRadius))
    path.addQuadCurve(
      to: CGPoint(x: rect.maxX - cornerRadius, y: rect.maxY),
      control: CGPoint(x: rect.maxX, y: rect.maxY))
    path.addLine(to: CGPoint(x: rect.maxX - cornerRadius - leg, y: rect.maxY))

    // Bottom-left
    path.move(to: CGPoint(x: rect.minX + cornerRadius + leg, y: rect.maxY))
    path.addLine(to: CGPoint(x: rect.minX + cornerRadius, y: rect.maxY))
    path.addQuadCurve(
      to: CGPoint(x: rect.minX, y: rect.maxY - cornerRadius),
      control: CGPoint(x: rect.minX, y: rect.maxY))
    path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY - cornerRadius - leg))

    return path
  }
}

/// The reticle stroked in the brand color, inset slightly from the edges.
struct ScannerReticle: View {
  var color: Color = .accentColor
  var lineWidth: CGFloat = 5

  var body: some View {
    ScannerReticleShape()
      .stroke(color, style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
      .shadow(color: color.opacity(0.5), radius: 6)
      .padding(22)
  }
}
