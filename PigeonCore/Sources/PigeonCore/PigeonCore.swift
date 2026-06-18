//
//  PigeonCore.swift
//  PigeonCore
//
//  A thin ergonomic layer over the generated UniFFI bindings (Generated/). The
//  generated types are already usable; these aliases just give the app
//  Pigeon-flavoured names and keep the `Ffi`-prefixed binding detail out of app
//  code. Anything richer (typed bundle wrappers, persistence helpers) is added
//  as the app actually needs it during the cutover.
//

/// One device's cryptographic account: its long-term Ed25519 identity plus its
/// Olm account. See `FfiAccount` for the full API.
public typealias PigeonAccount = FfiAccount

/// One end of a pairwise end-to-end-encrypted session (Olm Double Ratchet).
public typealias PigeonSession = FfiSession
