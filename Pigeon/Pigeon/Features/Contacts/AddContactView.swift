//
//  AddContactView.swift
//  Pigeon
//
//  Scan or paste a peer's QR card to add them. The contact's name comes from
//  their card; it can be edited later in the chat.
//

import SwiftUI

struct AddContactView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss

  @State private var pasted = ""
  @State private var error: String?
  @State private var showManualEntry = false
  @State private var showingMyQR = false
  @State private var showingMyFingerprint = false
  @State private var addedName: String?

  var body: some View {
    NavigationStack {
      content
        .navigationTitle("Add Contact")
        .navigationBarTitleDisplayMode(.inline)
        .maxBrightness(while: showingMyQR)  // full brightness while showing our QR
        .toolbar {
          ToolbarItem(placement: .cancellationAction) {
            Button(addedName == nil ? "Cancel" : "Done") { dismiss() }
          }
        }
    }
  }

  private var content: some View {
    ScrollView {
      VStack(spacing: 24) {
        scanPanel
        scannerHint
        errorLabel
        manualEntry
      }
      .padding()
    }
  }

  private var scannerHint: some View {
    Text(scannerHintText)
      .font(.callout)
      .foregroundStyle(.secondary)
      .multilineTextAlignment(.center)
      .padding(.horizontal)
  }

  private var scannerHintText: String {
    if let addedName {
      return "Added \(addedName). Now have them scan your QR code to add you back."
    }
    return showingMyQR
      ? "Have the other person scan this QR code to add you."
      : "Point your camera at the other person's Pigeon QR code."
  }

  @ViewBuilder
  private var errorLabel: some View {
    if let error {
      Label(error, systemImage: "exclamationmark.triangle.fill")
        .font(.footnote)
        .foregroundStyle(.red)
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
    }
  }

  private var scanPanel: some View {
    VStack(spacing: 12) {
      scannerFrame
      scanToggleButton
    }
  }

  private var scannerFrame: some View {
    ZStack {
      if showingMyQR {
        myQRCode
      } else {
        QRScanner { code in handle(code) }
        ScannerReticle()
      }
    }
    .aspectRatio(1, contentMode: .fit)
    .frame(maxWidth: 340)
    .background(showingMyQR ? Color(.systemBackground) : .black)
    .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
    .overlay(
      RoundedRectangle(cornerRadius: 28, style: .continuous)
        .strokeBorder(.tint.opacity(0.25), lineWidth: 1)
    )
    .shadow(color: .black.opacity(0.15), radius: 12, y: 6)
  }

  private var scanToggleButton: some View {
    Button {
      withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
        showingMyQR.toggle()
      }
    } label: {
      Label(showingMyQR ? "Scan Contact QR" : "Show My QR", systemImage: "qrcode")
    }
    .buttonStyle(.bordered)
    .buttonBorderShape(.capsule)
  }

  private var myQRCode: some View {
    QRCode.image(from: session.myCard.encoded())
      .padding(24)
  }

  private var manualEntry: some View {
    DisclosureGroup(manualEntryTitle, isExpanded: $showManualEntry) {
      if showingMyFingerprint {
        myFingerprint
      } else {
        manualEntryFields
      }
    }
    .tint(.secondary)
    .padding()
    .background(.fill.quaternary, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
  }

  private var manualEntryTitle: String {
    showingMyFingerprint ? "My fingerprint" : "Enter a code manually"
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
      Button {
        withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
          showingMyFingerprint = true
        }
      } label: {
        Label("Show My Fingerprint", systemImage: "number")
          .frame(maxWidth: .infinity)
      }
      .buttonStyle(.bordered)
    }
    .padding(.top, 4)
  }

  private var myFingerprint: some View {
    VStack(spacing: 12) {
      Text(session.myFingerprint)
        .font(.callout.monospaced())
        .multilineTextAlignment(.center)
        .textSelection(.enabled)
      Button {
        withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
          showingMyFingerprint = false
        }
      } label: {
        Label("Enter Contact Code", systemImage: "keyboard")
          .frame(maxWidth: .infinity)
      }
      .buttonStyle(.bordered)
    }
    .padding(.top, 4)
  }

  private func handle(_ code: String) {
    guard let card = ContactCard(scanned: code) else {
      error = "That isn't a valid Pigeon contact code."
      return
    }
    let name = card.name.isEmpty ? "Unnamed" : card.name
    if session.addContact(card.bundle, name: name, relayURLs: card.relayURLs) {
      error = nil
      pasted = ""
      // Mutual exchange: once we've added them, flip to our own QR so the
      // other person can scan us back without leaving this screen.
      withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
        addedName = name
        showingMyFingerprint = false
        showingMyQR = true
      }
    } else {
      error = "Couldn't add this contact (invalid binding, or it's your own code)."
    }
  }
}
