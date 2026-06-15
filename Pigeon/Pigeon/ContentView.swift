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

  var body: some View {
    content
      .overlay(alignment: .top) {
        if let banner = session.banner {
          bannerView(banner)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
      }
      .animation(.spring(duration: 0.3), value: session.banner)
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
}
