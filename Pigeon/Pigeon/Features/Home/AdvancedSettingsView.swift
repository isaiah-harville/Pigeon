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

  var body: some View {
    List {
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
    .navigationTitle("Advanced Settings")
    .navigationBarTitleDisplayMode(.inline)
    .onAppear { receiveWhileLocked = session.backgroundDeliveryEnabled }
  }
}
