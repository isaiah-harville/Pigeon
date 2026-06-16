# Contributing to the App

Read the root [CONTRIBUTING.md](../CONTRIBUTING.md) first.

App changes should preserve the separation between UI, session orchestration,
transport, storage, and reusable package code.

## Checks

```sh
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
swiftlint lint --strict
swift-format lint --recursive --parallel Pigeon
```

## App-specific expectations

- Do not weaken Keychain accessibility to make background behavior easier.
- Do not imply a contact is verified before the safety-number flow supports that
  claim.
- Keep relay UI honest: relays cannot read content, but they can observe
  connection metadata.
- Keep contact-card, relay, storage, and session behavior reflected in docs when
  those formats or flows change.
