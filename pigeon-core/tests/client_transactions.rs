use pigeon_core::{
    ClientCommand, Error, IdentityError, IdentityPurpose, MemoryStateStore, PigeonClient,
    SecureIdentity, StateStore,
};

#[derive(Default)]
struct TestIdentity;

impl SecureIdentity for TestIdentity {
    fn ensure_public_key(&self, purpose: IdentityPurpose) -> Result<[u8; 32], IdentityError> {
        Ok(match purpose {
            IdentityPurpose::Root => [1; 32],
            IdentityPurpose::Mls => [2; 32],
            IdentityPurpose::Relay => [3; 32],
            IdentityPurpose::GroupCapability(_) => [4; 32],
            IdentityPurpose::GroupRecovery(_) => [5; 32],
        })
    }

    fn sign(&self, _purpose: IdentityPurpose, _message: &[u8]) -> Result<[u8; 64], IdentityError> {
        Ok([9; 64])
    }
}

fn create_group() -> ClientCommand {
    ClientCommand::create_group(
        "command-1",
        "Friends",
        vec![[2; 32], [3; 32]],
        "https://relay.example",
        false,
    )
    .unwrap()
}

#[test]
fn failed_checkpoint_releases_no_event_or_outbound() {
    let store = MemoryStateStore::failing_on_replace();
    let mut client = PigeonClient::new(store, TestIdentity).unwrap();

    let error = client.execute(create_group()).unwrap_err();

    assert!(matches!(error, Error::Persistence(_)));
    assert_eq!(client.checkpoint_generation(), 0);
    assert!(client.store().load().unwrap().is_none());
}

#[test]
fn output_is_released_only_after_the_checkpoint_advances() {
    let store = MemoryStateStore::default();
    let mut client = PigeonClient::new(store, TestIdentity).unwrap();

    let output = client.execute(create_group()).unwrap();

    assert_eq!(output.checkpoint_generation, 1);
    assert_eq!(output.events.len(), 1);
    assert_eq!(output.outbound.len(), 2);
    assert_eq!(client.checkpoint_generation(), 1);
    assert_eq!(client.store().load().unwrap().unwrap().generation, 1);
}
