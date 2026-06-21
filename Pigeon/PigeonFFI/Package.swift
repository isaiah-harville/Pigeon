// swift-tools-version: 6.2
//
// PigeonFFI — Swift access to the Rust `pigeon-core` messaging core (Olm via the
// audited `vodozemac`) and the `pigeon-mesh` transport layer. The compiled Rust
// lives in PigeonFFIBindings.xcframework and the generated UniFFI bindings live
// in Sources/PigeonFFI/Generated; both are produced by
// `pigeon-ffi/build-xcframework.sh`. Do not hand-edit the generated files —
// regenerate and commit instead (CI enforces this).
//
import PackageDescription

let package = Package(
  name: "PigeonFFI",
  platforms: [
    // Pigeon's supported floor (it ships as a Mac-designed-for-iPad build). The
    // macOS slice exists only so `swift test` can run the round-trip suite on
    // the host.
    .iOS(.v26),
    .macOS(.v26),
  ],
  products: [
    .library(name: "PigeonFFI", targets: ["PigeonFFI"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.38.0")
  ],
  targets: [
    .binaryTarget(name: "PigeonFFIBindings", path: "PigeonFFIBindings.xcframework"),
    .target(
      name: "PigeonFFI",
      dependencies: [
        "PigeonFFIBindings",
        .product(name: "SwiftProtobuf", package: "swift-protobuf"),
      ],
      swiftSettings: [
        .swiftLanguageMode(.v6)
      ]
    ),
    .testTarget(
      name: "PigeonFFITests",
      dependencies: ["PigeonFFI"]
    ),
  ]
)
