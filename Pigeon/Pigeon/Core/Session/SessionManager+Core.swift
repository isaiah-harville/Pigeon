import PigeonFFI

extension SessionManager {
  /// Atomically replaces the host projection with a snapshot from the durable
  /// core. A stale asynchronous result cannot roll the UI back.
  func applyCoreSnapshot(_ snapshot: PigeonCoreSnapshot) {
    guard snapshot.checkpointGeneration >= coreSnapshotGeneration else { return }
    groups = snapshot.groups
    coreSnapshotGeneration = snapshot.checkpointGeneration
  }
}
