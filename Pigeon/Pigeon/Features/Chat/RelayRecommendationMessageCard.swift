import SwiftUI

struct RelayRecommendationMessageCard: View {
  let urls: [String]
  let mine: Bool

  var body: some View {
    VStack(alignment: .leading, spacing: 9) {
      Label(mine ? "Relay Shared" : "Shared Relay", systemImage: "server.rack")
        .font(.caption.weight(.semibold))
      ForEach(urls, id: \.self) { string in
        if let url = URL(string: string) {
          RelayRecommendationRow(url: url, mine: mine)
        }
      }
    }
    .foregroundStyle(mine ? .white : .primary)
    .frame(minWidth: 210, alignment: .leading)
  }
}

private struct RelayRecommendationRow: View {
  @Environment(SessionManager.self) private var session
  let url: URL
  let mine: Bool

  @State private var probe: RelayPinger.Ping?
  @State private var showProbeWarning = false

  private var configured: Bool {
    RelaySettings.entries().contains { $0.url == url && $0.enabled }
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Text(url.host ?? url.absoluteString).font(.subheadline.weight(.semibold))
      probeStatus
      if !mine { actions }
    }
    .confirmationDialog(
      "Check this relay?", isPresented: $showProbeWarning, titleVisibility: .visible
    ) {
      Button("Check Relay") { startProbe() }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        "Connecting can reveal your IP address and timing to this endpoint. "
          + "Only continue if you recognize it.")
    }
  }

  @ViewBuilder
  private var probeStatus: some View {
    switch probe {
    case nil:
      Text("Not checked").foregroundStyle(.secondary)
    case .some(.measuring):
      Label("Checking PigeonWire…", systemImage: "hourglass")
    case .some(.unreachable):
      Label("Relay unavailable", systemImage: "exclamationmark.triangle")
        .foregroundStyle(.orange)
    case .some(.available(let milliseconds, let info)):
      let version = info.relayVersion.map { "Relay \($0)" } ?? "Relay version unavailable"
      switch info.compatibility {
      case .compatible:
        Label(
          "\(version) · PigeonWire compatible · \(milliseconds) ms",
          systemImage: "checkmark.circle"
        )
        .foregroundStyle(.green)
      case .updateRelay:
        Label("\(version) · relay update required", systemImage: "arrow.down.circle")
          .foregroundStyle(.orange)
      case .updateApp:
        Label("\(version) · update Pigeon", systemImage: "arrow.up.circle")
          .foregroundStyle(.orange)
      case .incompatible:
        Label("\(version) · incompatible", systemImage: "xmark.shield")
          .foregroundStyle(.red)
      }
    }
  }

  @ViewBuilder
  private var actions: some View {
    if configured {
      Label("Added", systemImage: "checkmark").font(.caption)
    } else if probe == nil {
      Button("Check Relay") {
        showProbeWarning = true
      }
      .buttonStyle(.bordered)
    } else {
      Button("Add Relay") { addRelay() }
        .buttonStyle(.bordered)
        .disabled(!isCompatible)
    }
  }

  private var isCompatible: Bool {
    guard case .some(.available(_, let info)) = probe else { return false }
    return info.compatibility == .compatible
  }

  private func addRelay() {
    guard isCompatible else { return }
    var entries = RelaySettings.entries()
    if let index = entries.firstIndex(where: { $0.url == url }) {
      entries[index].enabled = true
    } else {
      entries.append(RelayEntry(url: url, enabled: true))
    }
    session.setRelayEntries(entries)
  }

  private func startProbe() {
    probe = .measuring
    Task { probe = await RelayPinger.probe(url) }
  }
}
