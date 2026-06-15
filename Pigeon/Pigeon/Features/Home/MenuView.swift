//
//  MenuView.swift
//  Pigeon
//
//  The app hub, reachable from the home screen's menu button: your identity
//  (and QR code), Bluetooth status, and recent activity.
//

import SwiftUI

struct MenuView: View {
  @Environment(SessionManager.self) private var session
  @Environment(IdentityManager.self) private var identity
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      List {
        Section {
          NavigationLink {
            IdentityQRView()
          } label: {
            HStack(spacing: 14) {
              ContactAvatar(
                name: session.myName,
                seed: identity.publicKey.rawRepresentation,
                size: 56)
              VStack(alignment: .leading, spacing: 2) {
                Text(session.myName.isEmpty ? "You" : session.myName)
                  .font(.title3.weight(.semibold))
                Label("Show my QR code", systemImage: "qrcode")
                  .font(.subheadline)
                  .foregroundStyle(.secondary)
              }
            }
            .padding(.vertical, 4)
          }
        }

        Section("Identity") {
          LabeledContent("Fingerprint", value: identity.publicKey.shortFingerprint)
            .font(.callout.monospaced())
        }

        Section("Bluetooth") {
          HStack {
            Label("Status", systemImage: "dot.radiowaves.left.and.right")
            Spacer()
            HStack(spacing: 6) {
              Circle().fill(statusColor).frame(width: 8, height: 8)
              Text(session.status.rawValue).foregroundStyle(.secondary)
            }
          }
          LabeledContent("Connected peers", value: "\(session.connectedPeerCount)")
        }

        if !session.log.isEmpty {
          Section("Activity") {
            ForEach(Array(session.log.suffix(12).enumerated()), id: \.offset) { _, line in
              Text(line)
                .font(.caption)
                .foregroundStyle(.secondary)
            }
          }
        }
      }
      .navigationTitle("Menu")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) {
          Button("Done") { dismiss() }
        }
      }
    }
  }

  private var statusColor: Color {
    if session.connectedPeerCount > 0 { return .green }
    switch session.status {
    case .scanning: return .orange
    case .idle: return .secondary
    case .unauthorized, .poweredOff: return .red
    }
  }
}
