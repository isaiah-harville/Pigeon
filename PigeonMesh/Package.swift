// swift-tools-version: 6.0
//
// PigeonMesh — platform-agnostic transport and mesh logic for Pigeon:
// packet framing, fragmentation/reassembly over small BLE MTUs, and (later)
// store-and-forward mesh routing. Dependency-free and unit-testable without
// a Bluetooth radio; the CoreBluetooth driver lives in the app and feeds bytes
// through this package.
//
import PackageDescription

let package = Package(
    name: "PigeonMesh",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "PigeonMesh", targets: ["PigeonMesh"]),
    ],
    targets: [
        .target(
            name: "PigeonMesh",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "PigeonMeshTests",
            dependencies: ["PigeonMesh"]
        ),
    ]
)
