//
//  ChatStatusComponents.swift
//  Pigeon
//
//  The chat header and link-picker chrome: encryption/verification state, the
//  live chosen-link status, and the relay/Bluetooth pickers. Split out of
//  ChatView+Components to keep each file focused (and within the lint limits).
//

import SwiftUI

/// The chat header: encryption state, an unverified-contact nudge, and the live
/// chosen-link status. Reads observable session state so it refreshes as the
/// session establishes and links come and go.
struct ChatStatusBanner: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact
  @Binding var showSafetyNumber: Bool

  private var isSecure: Bool { session.establishedContactIDs.contains(contact.id) }

  var body: some View {
    VStack(spacing: 2) {
      HStack(spacing: 6) {
        Image(systemName: isSecure ? "lock.fill" : "lock.open")
        Text(isSecure ? "End-to-end encrypted" : "Establishing secure session…")
        Spacer()
        if session.isEphemeral(contact) {
          Label("Ephemeral", systemImage: "clock.arrow.circlepath")
            .foregroundStyle(.orange)
        }
      }
      .foregroundStyle(isSecure ? .green : .secondary)
      if !session.isVerifiedInPerson(contact) {
        Button {
          showSafetyNumber = true
        } label: {
          HStack(spacing: 6) {
            Image(systemName: "exclamationmark.shield.fill")
            Text("Not verified in person — compare the safety number")
            Spacer()
          }
          .foregroundStyle(.orange)
        }
        .buttonStyle(.plain)
      }
      ConnectionSummary(contact: contact)
    }
    .font(.footnote)
    .padding(.horizontal)
    .padding(.vertical, 6)
    .background(.bar)
  }
}

/// The chat's chosen link and whether it can carry a message *right now*, shown
/// live in the header so users can tell at a glance if they're reachable over
/// the transport this chat uses — relay or Bluetooth. Reads observable
/// transport state, so the trailing dot and text refresh as links come and go.
struct ConnectionSummary: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    let local = session.usesBluetooth(contact)
    let reachable = session.chosenLinkReachable(for: contact)
    HStack(spacing: 6) {
      Image(systemName: local ? "dot.radiowaves.left.and.right" : "globe")
      Text(detail(local: local, reachable: reachable))
      Spacer()
      Circle()
        .fill(reachable ? Color.green : Color.secondary)
        .frame(width: 6, height: 6)
        .accessibilityLabel(reachable ? "Connected" : "Not connected")
    }
    .font(.caption2)
    .foregroundStyle(.secondary)
  }

  private func detail(local: Bool, reachable: Bool) -> String {
    if local {
      let peers = session.connectedPeerCount
      return reachable
        ? "Local · \(peers) peer\(peers == 1 ? "" : "s")" : "Local · waiting for peer"
    }
    if let host = session.relayHosts.first { return "Relay · \(host)" }
    return "Relay · connecting…"
  }
}

/// A thin pill above the composer to pick the chat's link. Relay is the default
/// (we encourage relays); Local is the opt-in second option, which floods both
/// nearby radios — Bluetooth mesh and same-network Wi-Fi — at once. Tap a segment
/// or swipe to switch; the choice is mirrored to the peer.
struct TransportPill: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    let local = session.usesBluetooth(contact)
    HStack(spacing: 2) {
      segment("Relay", "globe", selected: !local) {
        session.setChatUsesBluetooth(false, for: contact)
      }
      segment("Local", "dot.radiowaves.left.and.right", selected: local) {
        session.setChatUsesBluetooth(true, for: contact)
      }
    }
    .padding(3)
    .background(Capsule().fill(.fill.tertiary))
    .padding(.horizontal)
    .gesture(
      DragGesture(minimumDistance: 24).onEnded { value in
        session.setChatUsesBluetooth(value.translation.width > 0, for: contact)
      }
    )
    .animation(.easeInOut(duration: 0.15), value: local)
  }

  private func segment(
    _ title: String, _ symbol: String, selected: Bool, action: @escaping () -> Void
  ) -> some View {
    Button(action: action) {
      Label(title, systemImage: symbol)
        .font(.caption2.weight(.medium))
        .frame(maxWidth: .infinity)
        .padding(.vertical, 5)
        .foregroundStyle(selected ? AnyShapeStyle(.white) : AnyShapeStyle(.secondary))
        .background(
          selected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear), in: Capsule())
    }
    .buttonStyle(.plain)
  }
}

/// Lets the user pin a conversation to one of the contact's advertised relays,
/// or leave it automatic; hidden when the contact advertises none.
struct RelayPicker: View {
  @Environment(SessionManager.self) private var session
  let contact: Contact

  var body: some View {
    let relays = session.advertisedRelays(for: contact)
    if !relays.isEmpty {
      Picker("Relay for this chat", selection: selection) {
        Text("Automatic").tag(URL?.none)
        ForEach(relays, id: \.self) { url in
          Text(url.host ?? url.absoluteString).tag(URL?.some(url))
        }
      }
    }
  }

  private var selection: Binding<URL?> {
    Binding(
      get: { session.preferredRelay(for: contact) },
      set: { session.setPreferredRelay($0, for: contact) }
    )
  }
}
