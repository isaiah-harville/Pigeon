// swift-tools-version: 6.2
//
// PigeonCore — Swift access to the Rust `pigeon-core` messaging core (Olm via
// the audited `vodozemac`). The compiled Rust lives in PigeonCoreFFI.xcframework
// and the generated UniFFI bindings live in Sources/PigeonCore/Generated; both
// are produced by `pigeon-core-ffi/build-xcframework.sh`. Do not hand-edit the
// generated files — regenerate and commit instead (CI enforces this).
//
import PackageDescription

let package = Package(
  name: "PigeonCore",
  platforms: [
    // Pigeon's supported floor (it ships as a Mac-designed-for-iPad build). The
    // macOS slice exists only so `swift test` can run the round-trip suite on
    // the host.
    .iOS(.v26),
    .macOS(.v26),
  ],
  products: [
    .library(name: "PigeonCore", targets: ["PigeonCore"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.38.0")
  ],
  targets: [
    .binaryTarget(name: "PigeonCoreFFI", path: "PigeonCoreFFI.xcframework"),
    .target(
      name: "PigeonCore",
      dependencies: [
        "PigeonCoreFFI",
        .product(name: "SwiftProtobuf", package: "swift-protobuf"),
      ],
      swiftSettings: [
        .swiftLanguageMode(.v6)
      ]
    ),
    .testTarget(
      name: "PigeonCoreTests",
      dependencies: ["PigeonCore"]
    ),
  ]
)
