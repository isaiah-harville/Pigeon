//
//  Clipboard.swift
//  Pigeon
//
//  Clipboard write.
//

import UIKit

enum Clipboard {
  static func copy(_ string: String) {
    UIPasteboard.general.string = string
  }
}
