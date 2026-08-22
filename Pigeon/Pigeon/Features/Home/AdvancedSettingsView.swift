//
//  AdvancedSettingsView.swift
//  Pigeon
//
//  Security and recovery controls that most people should not need day to day.
//

import SwiftUI

struct AdvancedSettingsView: View {
  @Environment(SessionManager.self) private var session

  @State private var receiveWhileLocked = true
  @State private var connectivityEnabled = true

  var body: some View {
    List {
      faradaySection
      lockedDeliverySection
    }
    .navigationTitle("Advanced Settings")
    .navigationBarTitleDisplayMode(.inline)
    .onAppear {
      receiveWhileLocked = session.backgroundDeliveryEnabled
      connectivityEnabled = session.connectivityEnabled
    }
  }

  private var faradaySection: some View {
    Section {
      Toggle(isOn: $connectivityEnabled) {
        Label("Connectivity", systemImage: "antenna.radiowaves.left.and.right.slash")
      }
      .onChange(of: connectivityEnabled) { _, enabled in
        session.setConnectivityEnabled(enabled)
      }
    } header: {
      Text("Faraday")
    } footer: {
      Text("Turn off Bluetooth, local Wi-Fi discovery, and internet relays at once.")
    }
  }

  private var lockedDeliverySection: some View {
    Section {
      Toggle(isOn: $receiveWhileLocked) {
        Label("Receive while locked", systemImage: "bell.badge")
      }
      .onChange(of: receiveWhileLocked) { _, enabled in
        if !session.setBackgroundDeliveryEnabled(enabled) {
          receiveWhileLocked = session.backgroundDeliveryEnabled
        }
      }
    } footer: {
      Text(
        "Allows Pigeon to relaunch for new messages while your device is locked. "
          + "Notifications never include message content.")
    }
  }
}
