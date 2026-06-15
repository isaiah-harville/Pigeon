//
//  Clipboard.swift
//  Pigeon
//
//  Cross-platform clipboard write (iOS + macOS dev build).
//

import Foundation

#if os(iOS)
  import UIKit
#elseif os(macOS)
  import AppKit
#endif

enum Clipboard {
  static func copy(_ string: String) {
    #if os(iOS)
      UIPasteboard.general.string = string
    #elseif os(macOS)
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(string, forType: .string)
    #endif
  }
}
