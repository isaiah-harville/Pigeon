//
//  RemoteContactExchangeView.swift
//  Pigeon
//
//  Exchange signed public ContactCards with someone who is not nearby.
//

import SwiftUI

struct RemoteContactExchangeView: View {
  @Binding var code: String
  let myShareURL: URL?
  let onAdd: () -> Void
  let onShowFingerprint: () -> Void

  var body: some View {
    VStack(spacing: 12) {
      explanation
      codeField
      addButton
      shareButton
      fingerprintButton
    }
  }

  private var explanation: some View {
    Text(
      "Exchange contact links through a channel you already use. Remote contacts "
        + "stay unverified until you compare safety numbers."
    )
    .font(.footnote)
    .foregroundStyle(.secondary)
    .multilineTextAlignment(.center)
  }

  private var codeField: some View {
    TextField("Pigeon contact link or code", text: $code, axis: .vertical)
      .lineLimit(2...4)
      .font(.caption.monospaced())
      .textFieldStyle(.roundedBorder)
  }

  private var addButton: some View {
    Button(action: onAdd) {
      Text("Add Contact").frame(maxWidth: .infinity)
    }
    .buttonStyle(.borderedProminent)
    .disabled(code.isEmpty)
  }

  @ViewBuilder
  private var shareButton: some View {
    if let myShareURL {
      ShareLink(
        item: myShareURL,
        subject: Text("My Pigeon contact"),
        message: Text(
          "Add me in Pigeon, then send me your contact link too. "
            + "We should compare safety numbers before trusting the chat.")
      ) {
        Label("Share My Contact Link", systemImage: "square.and.arrow.up")
          .frame(maxWidth: .infinity)
      }
      .buttonStyle(.bordered)
    }
  }

  private var fingerprintButton: some View {
    Button(action: onShowFingerprint) {
      Label("Show My Fingerprint", systemImage: "number")
        .frame(maxWidth: .infinity)
    }
    .buttonStyle(.bordered)
  }
}
