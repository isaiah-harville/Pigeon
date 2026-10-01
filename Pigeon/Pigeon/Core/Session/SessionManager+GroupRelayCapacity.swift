import Foundation
import PigeonFFI

extension SessionManager {
  func bindGroupRelayCapacityCallbacks(to transport: GroupRelayTransport) {
    transport.onCapacity = { [weak self] groupID in
      self?.groupRelayCapacityLimited.insert(groupID)
    }
    transport.onCapacityAvailable = { [weak self] groupID in
      self?.groupRelayCapacityLimited.remove(groupID)
    }
  }

  func pendingGroupRegistrations(in snapshot: PigeonCoreSnapshot) -> Set<Data> {
    Set(
      snapshot.pendingOutbound.compactMap { item in
        guard let action = try? item.relayAction(), case .registration(let registration) = action
        else { return nil }
        return snapshot.groups.first { group in
          registration.capabilities.contains { $0.publicKey == group.capabilityPublicKey }
        }?.groupID
      })
  }
}
