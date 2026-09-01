import Foundation
import PigeonFFI

struct ContactPrekeyBundles {
  let chat: PigeonPrekeyBundle?
  let control: PigeonPrekeyBundle?
}

extension SessionManager {
  @discardableResult
  func addContact(
    _ bundle: PigeonIdentityBundle, name: String, relayURLs: [URL],
    prekeyBundle: PigeonPrekeyBundle?, admission: ContactAdmission
  ) -> Bool {
    addContact(
      bundle, name: name, relayURLs: relayURLs,
      prekeys: ContactPrekeyBundles(chat: prekeyBundle, control: nil), admission: admission)
  }

  /// Verifies and stores a scanned contact bundle, then begins establishing a
  /// session. Remotely imported contacts preserve durable request admission
  /// state when their public card is refreshed.
  @discardableResult
  func addContact(
    _ bundle: PigeonIdentityBundle, name: String, relayURLs: [URL],
    prekeys: ContactPrekeyBundles,
    admission: ContactAdmission
  ) -> Bool {
    guard bundle.identityKey != myID else {
      note(.ownIdentityScanned)
      return false
    }
    let chatPrekeys = prekeys.chat.flatMap { $0.identityKey == bundle.identityKey ? $0 : nil }
    let controlPrekeys = prekeys.control.flatMap { candidate in
      candidate.identityKey == bundle.identityKey ? candidate : nil
    }
    let sanitized = DisplayName.sanitize(name)
    let displayName = sanitized.isEmpty ? "Unnamed" : sanitized
    var contact = Contact(
      bundle: bundle, displayName: displayName, relayURLs: relayURLs,
      prekeyBundle: chatPrekeys, pairwiseControlPrekeyBundle: controlPrekeys,
      verifiedInPerson: admission.verifiedInPerson,
      requestState: admission.requestState)
    mergeExistingContactState(into: &contact, admission: admission)
    do {
      try registerPairwiseContactIfAvailable(contact)
    } catch {
      return false
    }
    replaceOrAppendContact(contact)
    activeConversationIDs.insert(bundle.identityKey)
    guard persist() else { return false }
    refreshRelay()
    note(.contactAdded)
    rehandshakeGate.clear(bundle.identityKey)
    resetSession(for: bundle.identityKey)
    establishIfNeeded(contactID: bundle.identityKey)
    return true
  }

  private func mergeExistingContactState(
    into contact: inout Contact, admission: ContactAdmission
  ) {
    guard let existing = contacts.first(where: { $0.id == contact.id }) else { return }
    if admission != .verifiedInPerson { contact.requestState = existing.requestState }
    contact.verifiedInPerson = existing.verifiedInPerson || admission.verifiedInPerson
    contact.introductionSent = existing.introductionSent
    contact.introductionReceived = existing.introductionReceived
    contact.requestCreatedAt = existing.requestCreatedAt
    contact.preferredRelayURL = existing.preferredRelayURL.flatMap { url in
      contact.relayURLs.contains(url) ? url : nil
    }
  }

  private func replaceOrAppendContact(_ contact: Contact) {
    if let index = contacts.firstIndex(where: { $0.id == contact.id }) {
      contacts[index] = contact
    } else {
      contacts.append(contact)
    }
  }
}
