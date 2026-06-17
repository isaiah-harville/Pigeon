//
//  CopiedToast.swift
//  Pigeon
//
//  Shared confirmation toast for clipboard actions.
//

import SwiftUI

struct CopiedToast: View {
  var body: some View {
    Label("Copied to clipboard", systemImage: "checkmark.circle.fill")
      .font(.subheadline.weight(.medium))
      .padding(.horizontal, 14)
      .padding(.vertical, 9)
      .background(.green, in: Capsule())
      .foregroundStyle(.white)
      .padding(.bottom, 24)
      .transition(.move(edge: .bottom).combined(with: .opacity))
  }
}
