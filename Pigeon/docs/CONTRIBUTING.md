# Contributing to the App

Read the root contributor guide first, then use `Pigeon/CONTRIBUTING.md` for
app-specific expectations.

## Checks

```sh
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO
swiftlint lint --strict
swift-format lint --recursive --parallel Pigeon
```
