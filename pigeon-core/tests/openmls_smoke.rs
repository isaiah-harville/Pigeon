use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn credential(
    identity: &[u8],
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    signer.store(provider.storage()).unwrap();
    let credential = BasicCredential::new(identity.to_vec());
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    )
}

#[test]
fn selected_openmls_release_creates_joins_and_encrypts() {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = credential(b"alice", &alice_provider);
    let (bob_credential, bob_signer) = credential(b"bob", &bob_provider);

    let bob_key_package = KeyPackage::builder()
        .build(CIPHERSUITE, &bob_provider, &bob_signer, bob_credential)
        .unwrap();
    let mut alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        alice_credential,
    )
    .unwrap();
    let (_, welcome, _) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome = match MlsMessageIn::from(welcome).extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("add_members must produce a Welcome"),
    };
    let staged = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap();
    let mut bob_group = staged.into_group(&bob_provider).unwrap();

    let message = alice_group
        .create_message(&alice_provider, &alice_signer, b"smoke")
        .unwrap();
    let processed = bob_group
        .process_message(
            &bob_provider,
            MlsMessageIn::from(message)
                .try_into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content() else {
        panic!("expected an MLS application message");
    };
    assert_eq!(application.into_bytes(), b"smoke");
}
