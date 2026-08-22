import Foundation

/// The sole app-layer session-init format. Olm authenticates establishment; the
/// signed public card supplies the peer profile needed for one-sided first
/// contact and must match the envelope/contact identity before admission.
struct SessionInitiationPayload: Codable, Equatable {
  private static let version = 1
  private static let maximumEncodedBytes = 64 * 1024

  let initiation: Data
  let contactCard: String
  private let version: Int

  init(initiation: Data, contactCard: String) {
    self.initiation = initiation
    self.contactCard = contactCard
    self.version = Self.version
  }

  func encoded() -> Data? {
    guard !initiation.isEmpty, !contactCard.isEmpty,
      let data = try? JSONEncoder().encode(self), data.count <= Self.maximumEncodedBytes
    else { return nil }
    return data
  }

  init?(decoding data: Data) {
    guard data.count <= Self.maximumEncodedBytes,
      let decoded = try? JSONDecoder().decode(Self.self, from: data),
      decoded.version == Self.version,
      !decoded.initiation.isEmpty,
      ContactCard(scanned: decoded.contactCard) != nil
    else { return nil }
    self = decoded
  }
}
