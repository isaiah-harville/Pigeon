//
//  ChatPresenter.swift
//  Pigeon
//
//  The chat-presentation slice of the session coordinator: in-app banners, the
//  local-notification hook, and the foreground/active-chat bookkeeping that
//  decides how an inbound message is surfaced. Extracted from SessionManager so
//  this UI concern is owned by one focused, observable type with no crypto or
//  transport coupling.
//

import Foundation

/// Owns how arriving messages are surfaced to the user and the foreground state
/// that gates it. `@Observable` so the in-app banner overlay updates live.
@MainActor
@Observable
final class ChatPresenter {

  /// A transient in-app banner shown when a message arrives in the foreground
  /// and the user isn't already viewing that chat.
  var banner: InAppBanner?
  /// The chat currently on screen (its notifications are suppressed while active).
  var activeChatID: Data?
  var isAppActive = true
  /// Called to surface a local notification when a message arrives while the
  /// app is backgrounded (wired by the app to `MessageNotifier`).
  var onIncomingNotification: (() -> Void)?

  func setAppActive(_ active: Bool) { isAppActive = active }
  func dismissBanner() { banner = nil }

  /// Surfaces an inbound message: stay silent if the user is already viewing
  /// that chat in the foreground; otherwise show an in-app banner (foreground)
  /// or post a local notification (backgrounded).
  func notifyIncoming(contactID: Data, title: String, body: String) {
    guard !(isAppActive && activeChatID == contactID) else { return }
    if isAppActive {
      showBanner(title: title, body: body)
    } else {
      onIncomingNotification?()
    }
  }

  /// Posts the content-free local notification directly, for cases without a
  /// foreground banner path (e.g. a deposit that arrived while locked).
  func notifyLocal() { onIncomingNotification?() }

  func showBanner(title: String, body: String) {
    let banner = InAppBanner(title: title, body: body)
    self.banner = banner
    Task {
      try? await Task.sleep(for: .seconds(3))
      if self.banner == banner { self.banner = nil }
    }
  }

  struct InAppBanner: Equatable, Identifiable {
    let id = UUID()
    let title: String
    let body: String
  }
}
