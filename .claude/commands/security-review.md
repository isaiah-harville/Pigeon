# Security Review

Review the current change or requested files with a security-first stance.

Use these references:

- `CLAUDE.md`
- `docs/SECURITY_MODEL.md`
- relevant source files under `Pigeon/Pigeon/Core/Identity/`
- relevant source files under `PigeonCrypto/Sources/PigeonCrypto/`

Focus on:

- secret handling and logging
- Keychain accessibility and identity reset behavior
- authentication of protocol headers and metadata
- replay, reordering, and dropped-message behavior
- KDF domain separation
- unsafe claims in UI or documentation
- missing tests for security-sensitive behavior

Lead with findings ordered by severity. Include file and line references. If no
issues are found, say so and name the remaining residual risk.
