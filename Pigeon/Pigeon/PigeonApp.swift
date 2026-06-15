//
//  PigeonApp.swift
//  Pigeon
//
//  Fully-offline, end-to-end-encrypted Bluetooth mesh messaging.
//

import SwiftUI

@main
struct PigeonApp: App {
    /// The device identity is loaded once at launch and shared via the
    /// environment. Failure here is fatal — without an identity the app
    /// cannot encrypt, sign, or be addressed.
    @State private var identity: IdentityManager

    init() {
        do {
            _identity = State(initialValue: try IdentityManager())
        } catch {
            fatalError("Failed to initialize device identity: \(error)")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(identity)
        }
    }
}
