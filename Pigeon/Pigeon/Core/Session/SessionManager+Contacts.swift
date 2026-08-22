import Foundation
import PigeonFFI

extension SessionManager {
  /// Verifies and stores a scanned contact bundle, then begins establishing a
  /// session. Remotely imported contacts preserve durable request admission
  /// state when their public card is refreshed.
  @discardableResult
  func addContact(
    _ bundle: PigeonIdentityBundle, name: String, relayURLs: [URL],
    prekeyBundle: PigeonPrekeyBundle?, admission: ContactAdmission
  ) -> Bool {
    guard bundle.identityKey != myID else {
      note(.ownIdentityScanned)
      return false
    }
    let prekeys = prekeyBundle.flatMap { $0.identityKey == bundle.identityKey ? $0 : nil }
    let sanitized = DisplayName.sanitize(name)
    let displayName = sanitized.isEmpty ? "Unnamed" : sanitized
    var contact = Contact(
      bundle: bundle, displayName: displayName, relayURLs: relayURLs,
      prekeyBundle: prekeys, verifiedInPerson: admission.verifiedInPerson,
      requestState: admission.requestState)
    if let index = contacts.firstIndex(where: { $0.id == bundle.identityKey }) {
      let existing = contacts[index]
      if admission != .verifiedInPerson { contact.requestState = existing.requestState }
      contact.verifiedInPerson = existing.verifiedInPerson || admission.verifiedInPerson
      contact.introductionSent = existing.introductionSent
      contact.introductionReceived = existing.introductionReceived
      contact.requestCreatedAt = existing.requestCreatedAt
      contact.preferredRelayURL = existing.preferredRelayURL.flatMap { url in
        relayURLs.contains(url) ? url : nil
      }
      contacts[index] = contact
    } else {
      contacts.append(contact)
    }
    activeConversationIDs.insert(bundle.identityKey)
    persist()
    refreshRelay()
    note(.contactAdded)
    rehandshakeGate.clear(bundle.identityKey)
    resetSession(for: bundle.identityKey)
    establishIfNeeded(contactID: bundle.identityKey)
    return true
  }
}
