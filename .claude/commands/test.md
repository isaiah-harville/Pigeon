# Test Pigeon

Run the relevant verification commands for this Swift project.

Start with:

```sh
swift test --package-path PigeonCrypto
```

Then, when app code changed, run:

```sh
xcodebuild build -project Pigeon/Pigeon.xcodeproj -scheme Pigeon -destination 'generic/platform=iOS'
```

If a command fails because sandboxing blocks SwiftPM or Clang cache writes,
explain that clearly and ask before rerunning with broader permissions.

Report:

- commands run
- pass/fail status
- important compiler or test output
- any tests that should exist but do not yet
