//
//  AddContactView.swift
//  Pigeon
//
//  Scan (iOS) or paste (macOS) a peer's QR card to add them. The contact's
//  name comes from their card; it can be edited later in the chat.
//

import SwiftUI

struct AddContactView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss

  @State private var pasted = ""
  @State private var error: String?
  @State private var showManualEntry = false

  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(spacing: 24) {
          #if os(iOS)
            scanner
            Text("Point your camera at the other person's Pigeon QR code.")
              .font(.callout)
              .foregroundStyle(.secondary)
              .multilineTextAlignment(.center)
              .padding(.horizontal)
          #endif

          if let error {
            Label(error, systemImage: "exclamationmark.triangle.fill")
              .font(.footnote)
              .foregroundStyle(.red)
              .multilineTextAlignment(.center)
              .frame(maxWidth: .infinity)
          }

          manualEntry
        }
        .padding()
      }
      .navigationTitle("Add Contact")
      #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
      #endif
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Cancel") { dismiss() }
        }
      }
    }
  }

  #if os(iOS)
    private var scanner: some View {
      ZStack {
        QRScanner { code in handle(code) }
        ScannerReticle()
      }
      .aspectRatio(1, contentMode: .fit)
      .frame(maxWidth: 340)
      .background(.black)
      .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
      .overlay(
        RoundedRectangle(cornerRadius: 28, style: .continuous)
          .strokeBorder(.tint.opacity(0.25), lineWidth: 1)
      )
      .shadow(color: .black.opacity(0.15), radius: 12, y: 6)
    }
  #endif

  @ViewBuilder
  private var manualEntry: some View {
    #if os(iOS)
      DisclosureGroup("Enter a code manually", isExpanded: $showManualEntry) {
        manualEntryFields
      }
      .tint(.secondary)
      .padding()
      .background(.fill.quaternary, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    #else
      VStack(alignment: .leading, spacing: 12) {
        Text("Paste their code").font(.headline)
        manualEntryFields
      }
      .padding()
      .background(.fill.quaternary, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    #endif
  }

  private var manualEntryFields: some View {
    VStack(spacing: 12) {
      TextField("Pigeon contact code", text: $pasted, axis: .vertical)
        .lineLimit(2...4)
        .font(.caption.monospaced())
        .textFieldStyle(.roundedBorder)
      Button {
        handle(pasted)
      } label: {
        Text("Add Contact").frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .disabled(pasted.isEmpty)
    }
    .padding(.top, 4)
  }

  private func handle(_ code: String) {
    guard let card = ContactCard(scanned: code) else {
      error = "That isn't a valid Pigeon contact code."
      return
    }
    let name = card.name.isEmpty ? "Unnamed" : card.name
    if session.addContact(card.bundle, name: name) {
      dismiss()
    } else {
      error = "Couldn't add this contact (invalid binding, or it's your own code)."
    }
  }
}
