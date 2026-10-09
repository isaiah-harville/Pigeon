import Foundation
import PigeonFFI

/// The shareable bearer ticket. Its URL fragment is never sent in an HTTP
/// request, but anyone who receives the full link can request membership.
struct GroupInviteLink {
  static let maximumLinkBytes = 8_192

  let ticket: Data
  let metadata: GroupInviteTicketView

  init?(ticket: Data) {
    self.init(ticket: ticket, now: .now)
  }

  init?(ticket: Data, now: Date) {
    guard ticket.count <= 4_096,
      let metadata = try? parseGroupInviteTicket(
        encoded: ticket, nowMs: Int64(now.timeIntervalSince1970 * 1_000))
    else { return nil }
    self.ticket = ticket
    self.metadata = metadata
  }

  init?(scanned value: String) {
    self.init(scanned: value, now: .now)
  }

  init?(scanned value: String, now: Date) {
    guard let ticket = Self.ticketBytes(from: value) else { return nil }
    self.init(ticket: ticket, now: now)
  }

  var shareURL: URL? { Self.url(for: ticket) }

  static func url(for ticket: Data) -> URL? {
    guard !ticket.isEmpty, ticket.count <= 4_096 else { return nil }
    var components = URLComponents()
    components.scheme = "https"
    components.host = "pigeonwire.app"
    components.path = "/group"
    components.fragment = "ticket=\(base64URL(ticket))"
    return components.url
  }

  static func ticketBytes(from value: String) -> Data? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.utf8.count <= maximumLinkBytes,
      let components = URLComponents(string: trimmed),
      components.scheme?.lowercased() == "https",
      components.host?.lowercased() == "pigeonwire.app",
      components.path == "/group",
      components.user == nil, components.password == nil,
      components.port == nil, components.query == nil,
      let fragment = components.fragment,
      fragment.hasPrefix("ticket=")
    else { return nil }
    let value = String(fragment.dropFirst("ticket=".count))
    guard !value.isEmpty,
      value.utf8.count <= 5_464,
      value.utf8.allSatisfy({ byte in
        (65...90).contains(byte) || (97...122).contains(byte)
          || (48...57).contains(byte) || byte == 45 || byte == 95
      })
    else { return nil }
    var standard = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
    guard let decoded = Data(base64Encoded: standard), decoded.count <= 4_096,
      base64URL(decoded) == value
    else { return nil }
    return decoded
  }

  private static func base64URL(_ value: Data) -> String {
    value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
