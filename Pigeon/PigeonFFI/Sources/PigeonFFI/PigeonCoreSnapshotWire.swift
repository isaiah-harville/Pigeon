extension PigeonCoreSnapshot {
  init(proto: Pigeon_Wire_V1_ClientSnapshot) throws {
    try self.init(
      checkpointGeneration: proto.checkpointGeneration,
      groups: proto.groups.map(PigeonGroupState.init(proto:)),
      pendingOutbound: proto.pendingOutbound.map(PigeonCoreOutboundItem.init(proto:)),
      pendingEvents: proto.pendingEvents.map(PigeonCoreEvent.init(proto:)),
      pairwisePrekeyBundle: proto.pairwisePrekeyBundle)
  }
}

extension PigeonGroupState {
  init(proto: Pigeon_Wire_V1_GroupState) {
    self.init(
      groupID: proto.groupID, ownerIdentity: proto.ownerIdentity,
      adminIdentities: proto.adminIdentities, memberIdentities: proto.memberIdentities,
      name: proto.name, relayURL: proto.relayURL, coordinationID: proto.coordinationID,
      meshEnabled: proto.meshEnabled, epoch: proto.epoch,
      policyRevision: proto.policyRevision, dissolved: proto.dissolved,
      capabilityPublicKey: proto.capabilityPublicKey,
      coordinatorPublicKey: proto.coordinatorPublicKey)
  }
}
