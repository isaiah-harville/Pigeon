// swift-tools-version: 6.0
//
// PigeonCrypto — clean-room Swift implementation of the Noise Protocol
// handshake and the Double Ratchet, built only on Apple CryptoKit primitives.
//
// Deliberately standalone and dependency-free so it can be audited and reused
// independently of the Pigeon app. NOT YET externally audited — see README.
//
import PackageDescription

let package = Package(
  name: "PigeonCrypto",
  platforms: [
    .iOS(.v17),
    .macOS(.v14),
  ],
  products: [
    .library(name: "PigeonCrypto", targets: ["PigeonCrypto"])
  ],
  // Documentation-only plugin. It is not a target dependency, so it is not
  // linked into PigeonCrypto or bundled with the app.
  dependencies: [
    .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.4.0")
  ],
  targets: [
    .target(
      name: "PigeonCrypto",
      swiftSettings: [
        .swiftLanguageMode(.v6)
      ]
    ),
    .testTarget(
      name: "PigeonCryptoTests",
      dependencies: ["PigeonCrypto"]
    ),
  ]
)
