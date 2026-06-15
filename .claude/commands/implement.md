# Implement Safely

Implement the requested Pigeon change.

Before editing:

1. Read `CLAUDE.md`.
2. Read `docs/SECURITY_MODEL.md` if the change touches identity, crypto, trust,
   storage, transport, pairing, or message handling.
3. Inspect the relevant local code paths with `rg` and direct file reads.

While editing:

- Keep the change small and reviewable.
- Preserve security invariants.
- Add or update focused tests when behavior changes.
- Do not introduce network, cloud sync, telemetry, or unaudited crypto
  dependencies without explicit approval.

Before finishing:

- Run `swift test --package-path PigeonCrypto` for crypto/package changes.
- Run the Xcode build command for app changes when practical.
- Summarize changed files, verification, and any security caveat.
