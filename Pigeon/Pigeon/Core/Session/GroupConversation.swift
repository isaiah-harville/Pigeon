import Foundation
import PigeonFFI

struct GroupConversation: Identifiable, Equatable, Codable {
  static let maximumProcessedEventIDs = 2_048

  let id: Data
  var messages: [GroupChatEntry] = []
  private(set) var processedEventIDs: [String] = []

  mutating func markProcessed(_ eventID: String) {
    processedEventIDs.append(eventID)
    if processedEventIDs.count > Self.maximumProcessedEventIDs {
      processedEventIDs.removeFirst(processedEventIDs.count - Self.maximumProcessedEventIDs)
    }
  }

  func hasProcessed(_ eventID: String) -> Bool {
    processedEventIDs.contains(eventID)
  }
}

struct GroupChatEntry: Identifiable, Equatable, Codable {
  let id: String
  let senderIdentity: Data?
  let mine: Bool
  let content: GroupChatContent
  let epoch: UInt64
  var date = Date()
  var delivery: GroupDeliverySummary?
  var reactions: [Data: String] = [:]
}

enum GroupChatContent: Equatable, Codable {
  case message(String, replyToMessageID: String?)
  case status(GroupStatusEvent)
  case securityWarning(code: UInt32, evidenceID: Data)
}

enum GroupStatusEvent: Equatable, Codable {
  case created(owner: Data)
  case memberAdded(actor: Data, subject: Data)
  case memberRemoved(actor: Data, subject: Data)
  case memberLeft(actor: Data, subject: Data)
  case adminPromoted(actor: Data, subject: Data)
  case adminDemoted(actor: Data, subject: Data)
  case nameChanged(actor: Data, name: String)
  case meshChanged(actor: Data, enabled: Bool)
  case relayChanged(actor: Data, relayURL: String)
  case dissolved(actor: Data)
}

struct GroupDeliverySummary: Equatable, Codable {
  let state: GroupDeliveryStatus
  let deliveredCount: UInt32
  let intendedCount: UInt32
}

enum GroupDeliveryStatus: String, Equatable, Codable {
  case sending
  case sent
  case deliveredTo = "delivered_to"
  case delivered
  case failed
  case expired
}

enum GroupEventReductionError: Error, Equatable {
  case invalidMessageID
  case invalidMessageBody
  case missingTargetMessage
  case unsupportedEvent
}
