//
//  ContentView.swift
//  Pigeon
//
//  Top-level router: unlock gate, name onboarding, then the chats home. The
//  in-app message banner is layered above whatever is showing.
//

import SwiftUI

struct ContentView: View {
  @Environment(SessionManager.self) private var session
  @AppStorage("pigeon.appearance") private var appearanceValue = AppAppearance.system.rawValue

  /// A contact link tapped elsewhere on the device, owned by the scene so it
  /// survives a launch that hasn't loaded identity yet.
  @Binding var pendingContactCode: String?
  @State private var showContactImport = false

  var body: some View {
    content
      .preferredColorScheme(appearance.colorScheme)
      .overlay(alignment: .top) {
        if let banner = session.banner {
          bannerView(banner)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
      }
      .animation(.spring(duration: 0.3), value: session.banner)
      .onAppear(perform: presentContactImportIfReady)
      .onChange(of: pendingContactCode) { presentContactImportIfReady() }
      .onChange(of: session.isUnlocked) { presentContactImportIfReady() }
      .onChange(of: session.myName) { presentContactImportIfReady() }
      .sheet(isPresented: $showContactImport, onDismiss: clearPendingContactCode) {
        // Keyed on the code so a second link arriving while the sheet is open
        // rebuilds the view; `initialCode` is only read when it's constructed.
        AddContactView(initialCode: pendingContactCode ?? "")
          .id(pendingContactCode)
      }
  }

  @ViewBuilder
  private var content: some View {
    if !session.isUnlocked {
      UnlockView()
    } else if session.myName.isEmpty {
      OnboardingNameView()
    } else {
      ChatsListView()
    }
  }

  private func bannerView(_ banner: SessionManager.InAppBanner) -> some View {
    HStack(spacing: 10) {
      Image(systemName: "bubble.left.fill").foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 1) {
        Text(banner.title).font(.subheadline.weight(.semibold))
        Text(banner.body).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
      }
      Spacer()
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
    .shadow(radius: 8, y: 2)
    .padding(.horizontal)
    .onTapGesture { session.dismissBanner() }
  }

  private var appearance: AppAppearance {
    AppAppearance(rawValue: appearanceValue) ?? .system
  }

  /// Holds a queued contact link until there's somewhere sensible to show it:
  /// after the unlock gate, and after the user has named themselves (otherwise
  /// the sheet lands on top of onboarding).
  private func presentContactImportIfReady() {
    guard pendingContactCode != nil, session.isUnlocked, !session.myName.isEmpty else { return }
    showContactImport = true
  }

  private func clearPendingContactCode() {
    pendingContactCode = nil
  }
}

enum AppAppearance: String, CaseIterable, Identifiable {
  case system
  case light
  case dark

  var id: String { rawValue }

  var label: String {
    switch self {
    case .system: return "System"
    case .light: return "Light"
    case .dark: return "Dark"
    }
  }

  var colorScheme: ColorScheme? {
    switch self {
    case .system: return nil
    case .light: return .light
    case .dark: return .dark
    }
  }
}
