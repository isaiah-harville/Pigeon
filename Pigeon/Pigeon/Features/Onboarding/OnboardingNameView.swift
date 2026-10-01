//
//  OnboardingNameView.swift
//  Pigeon
//
//  First-run step (after unlock): choose the display name shared in your QR
//  card so contacts who scan you are auto-named.
//

import SwiftUI

struct OnboardingNameView: View {
  @Environment(SessionManager.self) private var session
  @State private var name = ""

  private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

  var body: some View {
    content
      .padding()
  }

  private var content: some View {
    VStack(spacing: 24) {
      Spacer()
      Image(systemName: "person.crop.circle.badge.checkmark")
        .font(.system(size: 64))
        .foregroundStyle(.tint)
      Text("What's your name?")
        .font(.title.bold())
      Text(explanation)
        .font(.callout)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .padding(.horizontal)

      TextField("Your name", text: $name)
        .textFieldStyle(.roundedBorder)
        .padding(.horizontal, 40)
        .textInputAutocapitalization(.words)

      relayDisclosure

      Button {
        session.setMyName(trimmed)
      } label: {
        Text("Continue").frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .disabled(trimmed.isEmpty)
      .padding(.horizontal, 40)
      Spacer()
    }
  }

  private var relayDisclosure: some View {
    Text(
      "Pigeon connects to its recommended relay and enables content-free push by default. "
        + "The relay can see your IP address and connection times; Apple handles push delivery. "
        + "No account is required. You can disable either option in Relays."
    )
    .font(.footnote)
    .foregroundStyle(.secondary)
    .multilineTextAlignment(.center)
    .padding(.horizontal)
  }

  private var explanation: String {
    """
    This is shown to people who scan your QR code, so they don't have to type it. \
    You can change it anytime.
    """
  }
}
