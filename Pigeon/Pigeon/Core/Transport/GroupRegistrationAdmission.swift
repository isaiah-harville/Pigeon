import CryptoKit
import Foundation
import PigeonFFI

/// Matches the signed registration transcript used by the group relay. The
/// challenge binds work to these exact bytes, independent of JSON key order.
enum GroupRegistrationAdmission {
  nonisolated private static let registrationDomain = Data(
    "pigeon.relay.group.registration.v2".utf8)
  nonisolated private static let admissionDomain = Data("pigeon.relay.group.admission.v1".utf8)

  nonisolated static func transcript(_ registration: PigeonGroupRelayRegistration) throws -> Data {
    guard registration.coordinationID.count == 32,
      registration.permanentControllerPublicKey.count == 32,
      registration.capabilities.count <= 128
    else { throw RelayError.protocolError }
    var data = registrationDomain
    data.append(registration.coordinationID)
    appendBigEndian(registration.authorizationGeneration, to: &data)
    data.append(registration.permanentControllerPublicKey)
    appendBigEndian(UInt32(registration.capabilities.count), to: &data)
    for capability in registration.capabilities {
      guard capability.capabilityID.count == 32, capability.publicKey.count == 32 else {
        throw RelayError.protocolError
      }
      data.append(capability.capabilityID)
      data.append(capability.publicKey)
      data.append(capability.canAppend ? 1 : 0)
      data.append(capability.canRead ? 1 : 0)
      data.append(capability.canControl ? 1 : 0)
    }
    return data
  }

  nonisolated static func solve(
    transcript: Data, challenge: Data, difficulty: Int
  ) throws -> Data {
    guard challenge.count == 32, (0...32).contains(difficulty) else {
      throw RelayError.protocolError
    }
    var prefix = admissionDomain
    prefix.append(challenge)
    prefix.append(contentsOf: SHA256.hash(data: transcript))
    for counter in UInt64.min...UInt64.max {
      if counter.isMultiple(of: 4_096) { try Task<Never, Never>.checkCancellation() }
      var solution = Data()
      appendBigEndian(counter, to: &solution)
      var input = prefix
      input.append(solution)
      let digest = SHA256.hash(data: input)
      let bytes = Array(digest)
      let fullBytes = difficulty / 8
      let remainingBits = difficulty % 8
      if bytes.prefix(fullBytes).allSatisfy({ $0 == 0 })
        && (remainingBits == 0 || bytes[fullBytes] >> (8 - remainingBits) == 0)
      {
        return solution
      }
    }
    throw RelayError.protocolError
  }

  nonisolated private static func appendBigEndian<T: FixedWidthInteger>(
    _ value: T, to data: inout Data
  ) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }
}
