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

  @State private var receiveWhileLocked = true

  var body: some View {
    NavigationStack {
      menuList
        .navigationTitle("Menu")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { doneToolbar }
        .onAppear { receiveWhileLocked = session.backgroundDeliveryEnabled }
    }
  }

  private var menuList: some View {
    List {
      identityCardSection
      // fingerprintSection
      bluetoothSection
      relaySection
      privacySection
      activitySection
    }
  }

  private var privacySection: some View {
    Section {
      Toggle(isOn: $receiveWhileLocked) {
        Label("Receive while locked", systemImage: "bell.badge")
      }
      .onChange(of: receiveWhileLocked) { _, enabled in
        if !session.setBackgroundDeliveryEnabled(enabled) {
          receiveWhileLocked = session.backgroundDeliveryEnabled  // revert on failure
        }
      }
    } header: {
      Text("Privacy")
    } footer: {
      Text(backgroundDeliveryFooter)
    }
  }

  private var backgroundDeliveryFooter: String {
    """
    Notify you of new messages while your device is locked. This keeps your \
    identity key readable in the background after the first unlock. Turn it off \
    to make your keys readable only while unlocked, at the cost of background \
    notifications — an unlikely attack vector that only matters if you lose your \
    phone. Either way, message content is never previewed in a notification.
    """
  }

  private var identityCardSection: some View {
    Section {
      NavigationLink {
        IdentityQRView()
      } label: {
        identityCard
      }
    }
  }

  private var identityCard: some View {
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

  // private var fingerprintSection: some View {
  //   Section("Identity") {
  //     LabeledContent("Fingerprint", value: identity.publicKey.shortFingerprint)
  //       .font(.callout.monospaced())
  //   }
  // }

  private var bluetoothSection: some View {
    Section("Bluetooth") {
      HStack {
        Label("Status", systemImage: "dot.radiowaves.left.and.right")
        Spacer()
        statusIndicator
      }
      LabeledContent("Connected peers", value: "\(session.connectedPeerCount)")
    }
  }

  private var statusIndicator: some View {
    HStack(spacing: 6) {
      Circle().fill(statusColor).frame(width: 8, height: 8)
      Text(session.status.rawValue).foregroundStyle(.secondary)
    }
  }

  private var relaySection: some View {
    Section {
      NavigationLink {
        RelaySettingsView()
      } label: {
        relayRow
      }
    } footer: {
      Text(relayFooter)
    }
  }

  private var relayRow: some View {
    HStack {
      Label("Internet relays", systemImage: "antenna.radiowaves.left.and.right")
      Spacer()
      HStack(spacing: 6) {
        Circle().fill(relayColor).frame(width: 8, height: 8)
        Text(relayText).foregroundStyle(.secondary)
      }
    }
  }

  private var relayFooter: String {
    """
    Reach contacts who are out of Bluetooth range. \
    Relay servers are federated and open-sourced — we encourage you to host your own.
    """
  }

  @ViewBuilder
  private var activitySection: some View {
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

  @ToolbarContentBuilder
  private var doneToolbar: some ToolbarContent {
    ToolbarItem(placement: .confirmationAction) {
      Button("Done") { dismiss() }
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

  private var relayColor: Color {
    switch session.relayLinkState {
    case .online: return .green
    case .connecting: return .orange
    case .failed: return .red
    case .disabled: return .secondary
    }
  }

  private var relayText: String {
    switch session.relayLinkState {
    case .online: return "Connected"
    case .connecting: return "Connecting…"
    case .failed: return "Unreachable"
    case .disabled: return "Off"
    }
  }
}
