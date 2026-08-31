import Foundation

extension GroupRelayProtocol {
  nonisolated private static var maximumDecodedEntries: Int { 512 }

  nonisolated static func classify(_ object: [String: Any]) -> ServerFrame {
    switch object["type"] as? String {
    case "compatible": return compatibility(object, compatible: true)
    case "incompatible": return compatibility(object, compatible: false)
    case "challenge":
      return fixedData(object["nonce"], base64: true).map(ServerFrame.challenge) ?? .ignored
    case "registered": return .registered
    case "appended": return uint64(object["sequence"]).map(ServerFrame.appended) ?? .ignored
    case "entries": return entries(object["entries"])
    case "wake": return .wake
    case "ok": return .ok
    case "error": return .error(object["message"] as? String ?? "error")
    case "coordinator_key":
      return fixedData(object["public_key"], base64: false)
        .map(ServerFrame.coordinatorKey) ?? .ignored
    case "coordinator_receipt":
      return receipt(object["receipt"]).map(ServerFrame.coordinatorReceipt) ?? .ignored
    case "coordinator_candidates": return candidates(object["candidates"])
    default: return .ignored
    }
  }

  nonisolated private static func compatibility(
    _ object: [String: Any], compatible: Bool
  ) -> ServerFrame {
    guard let protocolVersion = int(object["protocol_version"]) else { return .ignored }
    let relayVersion = object["relay_version"] as? String
    return compatible
      ? .compatible(protocolVersion: protocolVersion, relayVersion: relayVersion)
      : .incompatible(protocolVersion: protocolVersion, relayVersion: relayVersion)
  }

  nonisolated private static func entries(_ value: Any?) -> ServerFrame {
    guard let objects = value as? [[String: Any]], objects.count <= maximumDecodedEntries else {
      return .ignored
    }
    var result: [Entry] = []
    result.reserveCapacity(objects.count)
    for object in objects {
      guard let sequence = uint64(object["sequence"]),
        let timestamp = uint64(object["timestamp"]),
        let encoded = object["ciphertext"] as? String,
        let ciphertext = Data(base64Encoded: encoded)
      else { return .ignored }
      result.append(Entry(sequence: sequence, ciphertext: ciphertext, timestamp: timestamp))
    }
    return .entries(result)
  }

  nonisolated private static func candidates(_ value: Any?) -> ServerFrame {
    guard let objects = value as? [[String: Any]], objects.count <= maximumDecodedEntries else {
      return .ignored
    }
    var result: [CoordinatorCandidate] = []
    result.reserveCapacity(objects.count)
    for object in objects {
      guard let receipt = receipt(object["receipt"]),
        let encoded = object["candidate"] as? String,
        let candidate = Data(base64Encoded: encoded),
        let timestamp = uint64(object["timestamp"])
      else { return .ignored }
      result.append(
        CoordinatorCandidate(receipt: receipt, candidate: candidate, timestamp: timestamp))
    }
    return .coordinatorCandidates(result)
  }

  nonisolated private static func receipt(_ value: Any?) -> CoordinatorReceipt? {
    guard let object = value as? [String: Any],
      let coordinationID = fixedData(object["coordination_id"], base64: false),
      let sequence = uint64(object["sequence"]),
      let priorReceiptHash = fixedData(object["prior_receipt_hash"], base64: false),
      let claimedBaseEpoch = uint64(object["claimed_base_epoch"]),
      let entryHash = fixedData(object["entry_hash"], base64: false),
      let encodedSignature = object["signature"] as? String,
      let signature = Data(base64Encoded: encodedSignature), signature.count == 64
    else { return nil }
    return CoordinatorReceipt(
      coordinationID: coordinationID, sequence: sequence,
      priorReceiptHash: priorReceiptHash, claimedBaseEpoch: claimedBaseEpoch,
      entryHash: entryHash, signature: signature)
  }

  nonisolated private static func fixedData(_ value: Any?, base64: Bool) -> Data? {
    guard let encoded = value as? String else { return nil }
    let data = base64 ? Data(base64Encoded: encoded) : decodeHex(encoded)
    return data?.count == 32 ? data : nil
  }

  nonisolated private static func int(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
      return nil
    }
    let double = number.doubleValue
    guard double.rounded() == double, double >= 0, double <= Double(Int.max) else { return nil }
    return Int(double)
  }

  nonisolated private static func uint64(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
      return nil
    }
    let double = number.doubleValue
    guard double.rounded() == double, double >= 0, double <= Double(UInt64.max) else { return nil }
    return number.uint64Value
  }

  nonisolated private static func decodeHex(_ value: String) -> Data? {
    guard value.count.isMultiple(of: 2) else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    return Data(bytes)
  }
}
