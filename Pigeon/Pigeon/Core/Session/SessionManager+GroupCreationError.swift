extension SessionManager {
  enum GroupCreationError: Error, Equatable {
    case invalidName
    case invalidRoster
    case invalidRelay
    case unreachableMember
    case invalidCoordinatorKey
  }
}
