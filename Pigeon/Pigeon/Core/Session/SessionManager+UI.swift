//
//  SessionManager+UI.swift
//  Pigeon
//

import Foundation
import PigeonCrypto
import PigeonMesh

extension SessionManager {

  // MARK: - UI passthroughs

  var status: TransportStatus { mesh.status }
  var connectedPeerCount: Int { mesh.connectedPeerCount }
  var meshLog: [String] { mesh.log }

  /// Relay (internet) link state for the UI; `.disabled` when none configured.
  var relayLinkState: RelayTransport.LinkState { relay?.linkState ?? .disabled }
  /// The configured relay endpoints.
  var relayURLs: [URL] { RelaySettings.urls() }

  /// Persists and applies a new set of relay endpoints.
  func setRelayURLs(_ urls: [URL]) {
    RelaySettings.setURLs(urls)
    relay?.reconfigure(urls)
  }

  /// Our own shareable identity bundle (for display as a QR code).
  var myBundle: IdentityBundle { identity.identityBundle }

  /// Our shareable card (identity bundle + display name + the relays we can be
  /// reached at) for the QR, so scanners learn where to deposit for us.
  var myCard: ContactCard {
    ContactCard(name: myName, bundle: identity.identityBundle, relayURLs: RelaySettings.urls())
  }

  /// Sets the local user's own display name (shared in their QR card).
  func setMyName(_ name: String) {
    myName = name.trimmingCharacters(in: .whitespacesAndNewlines)
    persist()
  }

  /// Renames a contact locally (does not affect their card).
  func renameContact(_ contact: Contact, to name: String) {
    guard let index = contacts.firstIndex(where: { $0.id == contact.id }) else { return }
    contacts[index].displayName = name.trimmingCharacters(in: .whitespacesAndNewlines)
    persist()
  }

  /// The safety number to compare in person with `contact`.
  func safetyNumber(with contact: Contact) -> String {
    guard let remote = try? IdentityPublicKey(rawRepresentation: contact.bundle.identityKey) else {
      return "—"
    }
    return SafetyNumber.compute(local: identity.publicKey, remote: remote)
  }
}
