//
//  DocsBrowser.swift
//  Pigeon
//
//  An in-app browser for Pigeon's documentation, so links open without kicking
//  the user out to Safari. SFSafariViewController runs out of process and
//  shares nothing with the app, which suits an app that shouldn't be handling
//  web content itself.
//

import SafariServices
import SwiftUI

/// The documentation pages the app links to.
enum DocsLink {
  static let site = URL(string: "https://docs.pigeonwire.app/")!
  /// How to run your own zero-knowledge relay.
  static let hostARelay = URL(string: "https://docs.pigeonwire.app/host-a-relay/")!
}

/// Presents a URL in an in-app Safari view controller.
struct DocsBrowser: UIViewControllerRepresentable {
  let url: URL

  func makeUIViewController(context _: Context) -> SFSafariViewController {
    let configuration = SFSafariViewController.Configuration()
    configuration.entersReaderIfAvailable = false
    let controller = SFSafariViewController(url: url, configuration: configuration)
    controller.dismissButtonStyle = .done
    return controller
  }

  func updateUIViewController(_: SFSafariViewController, context _: Context) {}
}

extension View {
  /// Presents `url` in the in-app browser while `isPresented` is true.
  func docsBrowser(_ url: URL, isPresented: Binding<Bool>) -> some View {
    sheet(isPresented: isPresented) {
      DocsBrowser(url: url)
        .ignoresSafeArea()
    }
  }
}
