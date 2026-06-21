//
//  RelaySettingsView.swift
//  Pigeon
//
//  Configure the internet relays. The recommended relay is always present and on
//  by default; tap any relay to enable/disable it, or swipe to delete (the
//  recommended one can be disabled but not removed). Disabling all relays makes
//  Pigeon fully serverless again — peers are reached only over Bluetooth. Each
//  relay shows its measured ping and the list sorts fastest-first. See
//  SECURITY_MODEL §6.1 for the metadata trade-off.
//

import SwiftUI

struct RelaySettingsView: View {
  @Environment(SessionManager.self) private var session

  @State private var entries: [RelayEntry] = []
  @State private var newURL = ""
  @State private var pinger = RelayPinger()
  @State private var pushEnabled = RelaySettings.pushEnabled

  var body: some View {
    relayList
      .navigationTitle("Relays")
      .navigationBarTitleDisplayMode(.inline)
      .onAppear {
        entries = session.relayEntries
        pinger.start(urls: entries.map(\.url))
      }
      .onDisappear { pinger.stop() }
      .onChange(of: entries.map(\.url)) { _, urls in pinger.start(urls: urls) }
  }

  private var relayList: some View {
    List {
      statusSection
      relaysSection
      pushSection
    }
    .animation(.default, value: sortedEntries)
  }

  private var pushSection: some View {
    Section {
      Toggle("Push wake-ups", isOn: $pushEnabled)
        .onChange(of: pushEnabled) { _, on in session.setPushEnabled(on) }
    } header: {
      Text("Notifications")
    } footer: {
      Text(
        """
        Let the official Pigeon relay wake the app with a notification when a \
        message is waiting, so it arrives even after the app is closed. The push \
        is content-free — it carries no sender or message, just a prompt to open \
        Pigeon. Your device gets a push token that the official relay (and Apple) \
        can link to "this mailbox has mail" — more metadata than the relay alone. \
        On by default; turn it off to rely on best-effort background reception. \
        Self-hosted relays don't push.
        """
      )
    }
  }

  private var statusSection: some View {
    Section {
      HStack(spacing: 8) {
        Circle().fill(stateColor).frame(width: 8, height: 8)
        Text(stateText).foregroundStyle(.secondary)
      }
    } header: {
      Text("Status")
    }
  }

  private var relaysSection: some View {
    Section {
      relaysRows
      addRelayRow
    } header: {
      Text("Relays")
    } footer: {
      Text(relaysFooter)
    }
  }

  /// Relays sorted fastest-first; unknown/unreachable sink to the bottom.
  private var sortedEntries: [RelayEntry] {
    entries.sorted { pingRank($0.url) < pingRank($1.url) }
  }

  private func pingRank(_ url: URL) -> Int {
    if case .ms(let ms) = pinger.pings[url] { return ms }
    return .max
  }

  private var relaysRows: some View {
    ForEach(sortedEntries, id: \.url) { entry in
      relayRow(entry)
        .swipeActions(edge: .trailing) {
          if entry.url != RelaySettings.recommendedURL {
            Button(role: .destructive) {
              remove(entry)
            } label: {
              Label("Delete", systemImage: "trash")
            }
          }
        }
    }
  }

  private func relayRow(_ entry: RelayEntry) -> some View {
    Button {
      toggle(entry)
    } label: {
      HStack(spacing: 10) {
        Image(systemName: entry.enabled ? "checkmark.circle.fill" : "circle")
          .foregroundStyle(entry.enabled ? Color.accentColor : Color.secondary)
        Text(entry.url.absoluteString)
          .font(.callout.monospaced())
          .lineLimit(1)
          .truncationMode(.middle)
          .foregroundStyle(entry.enabled ? .primary : .secondary)
        if entry.url == RelaySettings.recommendedURL {
          Image(systemName: "checkmark.seal.fill")
            .font(.footnote)
            .foregroundStyle(.tint)
            .accessibilityLabel("Verified Pigeon relay")
        }
        Spacer(minLength: 8)
        pingLabel(entry.url)
      }
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
  }

  @ViewBuilder
  private func pingLabel(_ url: URL) -> some View {
    switch pinger.pings[url] {
    case .ms(let ms):
      Text("\(ms) ms")
        .font(.caption.monospacedDigit())
        .foregroundStyle(pingColor(ms))
    case .unreachable:
      Text("offline")
        .font(.caption)
        .foregroundStyle(.red)
    case .measuring, .none:
      ProgressView().controlSize(.mini)
    }
  }

  private func pingColor(_ ms: Int) -> Color {
    switch ms {
    case ..<100: return .green
    case ..<300: return .orange
    default: return .red
    }
  }

  private var addRelayRow: some View {
    HStack {
      TextField(RelaySettings.recommendedURL.absoluteString, text: $newURL)
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .font(.callout.monospaced())
        .onSubmit(add)
      Button("Add", action: add)
        .disabled(!RelaySettings.isValidEndpoint(newURL))
    }
  }

  private var relaysFooter: String {
    """
    Pigeon deposits end-to-end-encrypted ciphertext for your contacts on enabled \
    relays so they can reach you off Bluetooth. Tap to enable or disable a relay; \
    swipe to delete. Use wss:// (TLS). A relay never sees message content, but \
    does see connection metadata.
    """
  }

  // MARK: - Mutations

  private func toggle(_ entry: RelayEntry) {
    guard let index = entries.firstIndex(where: { $0.url == entry.url }) else { return }
    entries[index].enabled.toggle()
    save()
  }

  private func remove(_ entry: RelayEntry) {
    guard entry.url != RelaySettings.recommendedURL else { return }
    entries.removeAll { $0.url == entry.url }
    save()
  }

  private func add() {
    let trimmed = newURL.trimmingCharacters(in: .whitespaces)
    guard RelaySettings.isValidEndpoint(trimmed), let url = URL(string: trimmed),
      !entries.contains(where: { $0.url == url })
    else { return }
    entries.append(RelayEntry(url: url, enabled: true))
    newURL = ""
    save()
  }

  private func save() {
    session.setRelayEntries(entries)
  }

  // MARK: - Status

  private var stateColor: Color {
    switch session.relayLinkState {
    case .online: return .green
    case .connecting: return .orange
    case .failed: return .red
    case .disabled: return .secondary
    }
  }

  private var stateText: String {
    switch session.relayLinkState {
    case .online: return "Connected"
    case .connecting: return "Connecting…"
    case .failed: return "Unreachable"
    case .disabled: return "No relays enabled"
    }
  }
}
