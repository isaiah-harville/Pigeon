# Diagnostic privacy

Pigeon diagnostics are an in-memory, bounded aid for local troubleshooting. They
must never contain plaintext or ciphertext, keys, fingerprints, contact names,
peer identifiers, relay addresses, payload sizes, raw errors, or message ids.

App, session, BLE, local Wi-Fi, and relay events use the closed
`DiagnosticEvent` enum. Its cases have no associated values and render fixed
strings. Debug builds retain all events. Release builds retain only the safe,
actionable failure subset and no routine connection activity.

The Rust cryptography, mesh, and relay packages do not log per-message data or
addresses. Relay process startup may report configuration state, but must not
emit mailbox addresses, device tokens, envelope ids, ciphertext, or request
bodies. Tests should use synthetic identifiers and must not print secrets.
