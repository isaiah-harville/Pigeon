use ed25519_dalek::{Signature, VerifyingKey};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::{Signer as OpenMlsSigner, SignerError};
use prost::Message;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize};

use super::{IdentityPurpose, SecureIdentity};
use crate::Error;
use crate::storage::TransactionalOpenMlsStorage;
use crate::wire::{MAX_MLS_OBJECT_BYTES, proto};

const BINDING_DOMAIN: &[u8] = b"pigeon.identity.mls.v1";
const RESERVATION_DOMAIN: &[u8] = b"pigeon.mls.key-package.consumer.v1";
const BINDING_VERSION: u32 = 1;
const CIPHERSUITE_ID: u16 = 0x0001;
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct PlatformMlsSigner<'a, I: SecureIdentity>(&'a I);

impl<I: SecureIdentity> OpenMlsSigner for PlatformMlsSigner<'_, I> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.0
            .sign(IdentityPurpose::Mls, payload)
            .map(|signature| signature.to_vec())
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsIdentityBinding {
    version: u32,
    ciphersuite: u16,
    root_public_key: [u8; 32],
    mls_public_key: [u8; 32],
    signature: [u8; 64],
}

impl MlsIdentityBinding {
    pub fn create(identity: &impl SecureIdentity) -> Result<Self, Error> {
        let root_public_key = identity.ensure_public_key(IdentityPurpose::Root)?;
        let mls_public_key = identity.ensure_public_key(IdentityPurpose::Mls)?;
        let message = binding_message(root_public_key, mls_public_key);
        let signature = identity.sign(IdentityPurpose::Root, &message)?;
        Ok(Self {
            version: BINDING_VERSION,
            ciphersuite: CIPHERSUITE_ID,
            root_public_key,
            mls_public_key,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), Error> {
        if self.version != BINDING_VERSION || self.ciphersuite != CIPHERSUITE_ID {
            return Err(Error::UnsupportedVersion {
                kind: "MLS identity binding",
                version: self.version,
            });
        }
        let key = VerifyingKey::from_bytes(&self.root_public_key).map_err(|_| Error::InvalidKey)?;
        key.verify_strict(
            &binding_message(self.root_public_key, self.mls_public_key),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::InvalidSignature)
    }

    pub fn root_public_key(&self) -> [u8; 32] {
        self.root_public_key
    }

    pub fn mls_public_key(&self) -> [u8; 32] {
        self.mls_public_key
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(4 + 2 + 32 + 32 + 64);
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(&self.ciphersuite.to_be_bytes());
        output.extend_from_slice(&self.root_public_key);
        output.extend_from_slice(&self.mls_public_key);
        output.extend_from_slice(&self.signature);
        output
    }

    fn to_proto(&self) -> proto::MlsIdentityBinding {
        proto::MlsIdentityBinding {
            version: self.version,
            ciphersuite: u32::from(self.ciphersuite),
            root_public_key: self.root_public_key.to_vec(),
            mls_public_key: self.mls_public_key.to_vec(),
            signature: self.signature.to_vec(),
        }
    }

    fn from_proto(binding: proto::MlsIdentityBinding) -> Result<Self, Error> {
        Ok(Self {
            version: binding.version,
            ciphersuite: u16::try_from(binding.ciphersuite).map_err(|_| Error::InvalidKey)?,
            root_public_key: to_array(&binding.root_public_key)?,
            mls_public_key: to_array(&binding.mls_public_key)?,
            signature: binding
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ReservedKeyPackage {
    binding: MlsIdentityBinding,
    intended_consumer: [u8; 32],
    tls_bytes: Vec<u8>,
    package_hash: [u8; 32],
    reservation_signature: [u8; 64],
}

impl ReservedKeyPackage {
    pub fn issue(
        identity: &impl SecureIdentity,
        intended_consumer: [u8; 32],
        storage: &mut TransactionalOpenMlsStorage,
    ) -> Result<Self, Error> {
        let binding = MlsIdentityBinding::create(identity)?;
        let signer = PlatformMlsSigner(identity);
        let credential = CredentialWithKey {
            credential: BasicCredential::new(binding.encode()).into(),
            signature_key: binding.mls_public_key.to_vec().into(),
        };
        let key_package = KeyPackage::builder()
            .build(CIPHERSUITE, storage.provider(), &signer, credential)
            .map_err(|_| Error::InvalidKey)?;
        let tls_bytes = key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| Error::Serialization)?;
        let package_hash = Sha256::digest(&tls_bytes).into();
        let reservation_signature = identity.sign(
            IdentityPurpose::Root,
            &reservation_message(intended_consumer, package_hash),
        )?;
        Ok(Self {
            binding,
            intended_consumer,
            tls_bytes,
            package_hash,
            reservation_signature,
        })
    }

    pub fn verify_for(&self, consumer: [u8; 32]) -> Result<(), Error> {
        if consumer != self.intended_consumer {
            return Err(Error::InvalidSignature);
        }
        self.binding.verify()?;
        if <[u8; 32]>::from(Sha256::digest(&self.tls_bytes)) != self.package_hash {
            return Err(Error::InvalidSignature);
        }
        let root = VerifyingKey::from_bytes(&self.binding.root_public_key)
            .map_err(|_| Error::InvalidKey)?;
        root.verify_strict(
            &reservation_message(self.intended_consumer, self.package_hash),
            &Signature::from_bytes(&self.reservation_signature),
        )
        .map_err(|_| Error::InvalidSignature)?;

        let key_package = KeyPackageIn::tls_deserialize_exact(&self.tls_bytes)
            .map_err(|_| Error::Serialization)?;
        let credential = key_package.unverified_credential();
        if credential.credential.serialized_content() != self.binding.encode()
            || credential.signature_key.as_slice() != self.binding.mls_public_key
        {
            return Err(Error::InvalidSignature);
        }
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let validated = key_package
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::InvalidSignature)?;
        if validated.ciphersuite() != CIPHERSUITE {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    pub fn tls_bytes(&self) -> &[u8] {
        &self.tls_bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        proto::ReservedKeyPackage {
            binding: Some(self.binding.to_proto()),
            intended_consumer: self.intended_consumer.to_vec(),
            key_package: self.tls_bytes.clone(),
            package_hash: self.package_hash.to_vec(),
            reservation_signature: self.reservation_signature.to_vec(),
        }
        .encode_to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MLS_OBJECT_BYTES {
            return Err(Error::ResourceLimit("reserved KeyPackage bytes"));
        }
        let package = proto::ReservedKeyPackage::decode(bytes).map_err(|_| Error::Serialization)?;
        Ok(Self {
            binding: MlsIdentityBinding::from_proto(package.binding.ok_or(Error::Serialization)?)?,
            intended_consumer: to_array(&package.intended_consumer)?,
            tls_bytes: package.key_package,
            package_hash: to_array(&package.package_hash)?,
            reservation_signature: package
                .reservation_signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?,
        })
    }
}

#[derive(Clone, Default)]
pub struct KeyPackagePool {
    entries: Vec<(ReservedKeyPackage, bool)>,
}

impl KeyPackagePool {
    pub fn insert_for(
        &mut self,
        local_consumer: [u8; 32],
        package: ReservedKeyPackage,
    ) -> Result<(), Error> {
        package.verify_for(local_consumer)?;
        if self
            .entries
            .iter()
            .any(|(existing, _)| existing.package_hash == package.package_hash)
        {
            return Err(Error::InvalidSignature);
        }
        self.entries.push((package, false));
        Ok(())
    }

    pub fn consume(
        &mut self,
        issuer: [u8; 32],
        consumer: [u8; 32],
    ) -> Result<ReservedKeyPackage, Error> {
        let (package, consumed) = self
            .entries
            .iter_mut()
            .find(|(package, consumed)| {
                !*consumed
                    && package.binding.root_public_key == issuer
                    && package.intended_consumer == consumer
            })
            .ok_or(Error::InvalidKey)?;
        package.verify_for(consumer)?;
        *consumed = true;
        Ok(package.clone())
    }
}

fn binding_message(root: [u8; 32], mls: [u8; 32]) -> Vec<u8> {
    let mut message = BINDING_DOMAIN.to_vec();
    message.extend_from_slice(&BINDING_VERSION.to_be_bytes());
    message.extend_from_slice(&CIPHERSUITE_ID.to_be_bytes());
    message.extend_from_slice(&root);
    message.extend_from_slice(&mls);
    message
}

fn reservation_message(consumer: [u8; 32], package_hash: [u8; 32]) -> Vec<u8> {
    let mut message = RESERVATION_DOMAIN.to_vec();
    message.extend_from_slice(&consumer);
    message.extend_from_slice(&package_hash);
    message
}

fn to_array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::InvalidKey)
}
