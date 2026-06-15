//
//  RelaySettingsView.swift
//  Pigeon
//
//  Configure the optional internet relays. With none set, Pigeon is fully
//  serverless and reaches peers only over Bluetooth. Adding a relay lets you
//  exchange (still end-to-end-encrypted) messages with contacts who are out of
//  range — see SECURITY_MODEL §6.1 for the metadata trade-off.
//

import SwiftUI

struct RelaySettingsView: View {
  @Environment(SessionManager.self) private var session

  @State private var urls: [URL] = []
  @State private var newURL = ""

  var body: some View {
    List {
      Section {
        HStack(spacing: 8) {
          Circle().fill(stateColor).frame(width: 8, height: 8)
          Text(stateText).foregroundStyle(.secondary)
        }
      } header: {
        Text("Status")
      }

      Section {
        ForEach(urls, id: \.self) { url in
          Text(url.absoluteString)
            .font(.callout.monospaced())
            .lineLimit(1)
            .truncationMode(.middle)
        }
        .onDelete { offsets in
          urls.remove(atOffsets: offsets)
          save()
        }

        HStack {
          TextField("wss://relay.example.com/ws", text: $newURL)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .font(.callout.monospaced())
            .onSubmit(add)
          Button("Add", action: add)
            .disabled(!RelaySettings.isValidEndpoint(newURL))
        }
      } header: {
        Text("Relays")
      } footer: {
        Text(
          "Pigeon deposits end-to-end-encrypted ciphertext for your contacts on these relays so they can reach you off Bluetooth. Use wss:// (TLS). A relay never sees message content, but does see connection metadata."
        )
      }
    }
    .navigationTitle("Relays")
    .navigationBarTitleDisplayMode(.inline)
    .onAppear { urls = session.relayURLs }
  }

  private func add() {
    let trimmed = newURL.trimmingCharacters(in: .whitespaces)
    guard RelaySettings.isValidEndpoint(trimmed), let url = URL(string: trimmed),
      !urls.contains(url)
    else { return }
    urls.append(url)
    newURL = ""
    save()
  }

  private func save() {
    session.setRelayURLs(urls)
  }

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
    case .disabled: return "No relays configured"
    }
  }
}
