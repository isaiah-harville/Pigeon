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
  @State private var showHostingDocs = false

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
      .docsBrowser(DocsLink.hostARelay, isPresented: $showHostingDocs)
  }

  private var relayList: some View {
    List {
      statusSection
      relaysSection
      hostingSection
      pushSection
    }
    .animation(.default, value: sortedEntries)
  }

  /// Relays are federated and anyone can run one, so the settings screen points
  /// at the setup guide rather than treating hosting as an expert-only thing.
  private var hostingSection: some View {
    Section {
      Button {
        showHostingDocs = true
      } label: {
        HStack {
          Label("How to host a relay", systemImage: "server.rack")
          Spacer()
          Image(systemName: "arrow.up.right.square")
            .foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
      }
    } footer: {
      Text(
        """
        Run your own relay so your messages don't depend on anyone else's \
        server. The guide opens in Pigeon.
        """
      )
    }
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
    if case .available(let ms, _) = pinger.pings[url] { return ms }
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
        relayEndpointLabel(entry)
        if entry.url == RelaySettings.recommendedURL {
          Image(systemName: "checkmark.seal.fill")
            .font(.footnote)
            .foregroundStyle(.tint)
            .accessibilityLabel("Verified Pigeon relay")
        }
        if !RelaySettings.isSecureEndpoint(entry.url) {
          Image(systemName: "exclamationmark.triangle.fill")
            .font(.footnote)
            .foregroundStyle(.orange)
            .accessibilityLabel("Not encrypted in transit")
        }
        Spacer(minLength: 8)
        pingLabel(entry.url)
      }
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
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
    swipe to delete. A relay never sees message content, but does see connection \
    metadata. Prefer wss:// — a ws:// relay is flagged, since without TLS that \
    metadata is exposed to the network too.
    """
  }

}

// MARK: - Relay version status

extension RelaySettingsView {

  private func relayEndpointLabel(_ entry: RelayEntry) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(entry.url.absoluteString)
        .font(.callout.monospaced())
        .lineLimit(1)
        .truncationMode(.middle)
        .foregroundStyle(entry.enabled ? .primary : .secondary)
      relayVersionLabel(entry.url)
    }
  }

  @ViewBuilder
  private func pingLabel(_ url: URL) -> some View {
    switch pinger.pings[url] {
    case .available(let ms, let info):
      switch info.compatibility {
      case .compatible:
        Text("\(ms) ms")
          .font(.caption.monospacedDigit())
          .foregroundStyle(pingColor(ms))
      case .updateRelay:
        updateLabel("Update relay")
      case .updateApp:
        updateLabel("Update Pigeon")
      case .incompatible:
        updateLabel("Incompatible")
      }
    case .unreachable:
      Text("offline")
        .font(.caption)
        .foregroundStyle(.red)
    case .measuring, .none:
      if session.incompatibleRelayURLs.contains(url) {
        updateLabel("Incompatible")
      } else {
        ProgressView().controlSize(.mini)
      }
    }
  }

  @ViewBuilder
  private func relayVersionLabel(_ url: URL) -> some View {
    if case .available(_, let info) = pinger.pings[url] {
      Text(relayVersionText(info))
        .font(.caption2.monospaced())
        .foregroundStyle(.secondary)
    }
  }

  private func relayVersionText(_ info: RelayTransport.RelayInfo) -> String {
    let release = info.relayVersion.map { "Relay \($0)" } ?? "Relay version unavailable"
    if let selected = info.selectedProtocolVersion {
      return "\(release) · Protocol \(selected)"
    }
    if let minimum = info.minimumProtocolVersion, let maximum = info.maximumProtocolVersion {
      let range = minimum == maximum ? "\(minimum)" : "\(minimum)–\(maximum)"
      return "\(release) · Protocol \(range)"
    }
    return release
  }

  private func updateLabel(_ text: String) -> some View {
    Text(text)
      .font(.caption)
      .foregroundStyle(.red)
  }

  private func pingColor(_ ms: Int) -> Color {
    switch ms {
    case ..<100: return .green
    case ..<300: return .orange
    default: return .red
    }
  }
}

// MARK: - Mutations & status

extension RelaySettingsView {

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

  private var stateColor: Color {
    switch session.relayLinkState {
    case .online: return .green
    case .connecting: return .orange
    case .failed: return .red
    case .incompatible: return .red
    case .disabled: return .secondary
    }
  }

  private var stateText: String {
    switch session.relayLinkState {
    case .online: return "Connected"
    case .connecting: return "Connecting…"
    case .failed: return "Unreachable"
    case .incompatible: return "Incompatible with this app version"
    case .disabled: return "No relays enabled"
    }
  }
}
