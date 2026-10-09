import Foundation
import PigeonFFI

extension SessionManager {
  func setChatUsesBluetooth(_ useBluetooth: Bool, for contact: Contact) {
    guard let current = contacts.first(where: { $0.id == contact.id }),
      current.requestState == .none
    else { return }
    guard bluetoothChatIDs.contains(contact.id) != useBluetooth else { return }
    applyTransport(useBluetooth: useBluetooth, for: contact.id, announce: true)
    sendTransportState(to: contact)
  }

  func applyTransport(useBluetooth: Bool, for contactID: Data, announce: Bool) {
    let changed = bluetoothChatIDs.contains(contactID) != useBluetooth
    if useBluetooth {
      bluetoothChatIDs.insert(contactID)
    } else {
      bluetoothChatIDs.remove(contactID)
    }
    if changed && announce {
      record(
        ChatMessage(
          mine: false, text: transportNotice(useBluetooth: useBluetooth, contactID: contactID),
          system: true),
        for: contactID)
    }
    persist()
    if changed, let contact = contacts.first(where: { $0.id == contactID }) {
      sendPending(to: contact)
    }
  }

  func sendTransportState(to contact: Contact) {
    guard let current = contacts.first(where: { $0.id == contact.id }),
      current.requestState == .none,
      canUseCorePairwise(with: current)
    else { return }
    let mode: PigeonDirectTransportMode =
      bluetoothChatIDs.contains(current.id) ? .local : .relay
    _ = try? sendDirectCoreApplication(.transportState(mode), id: UUID(), to: current)
  }

  private func transportNotice(useBluetooth: Bool, contactID: Data) -> String {
    if useBluetooth { return "Switched to Local" }
    if let host = relayHost(for: contactID) { return "Switched to relay · \(host)" }
    return "Switched to relay"
  }
}
