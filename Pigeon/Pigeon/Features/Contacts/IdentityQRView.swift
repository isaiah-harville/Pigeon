//
//  IdentityQRView.swift
//  Pigeon
//
//  Shows this device's identity as a QR code for a peer to scan in person.
//  Tap your name to edit it (the QR regenerates); tap the fingerprint to copy.
//

import SwiftUI

struct IdentityQRView: View {
  @Environment(SessionManager.self) private var session
  @Environment(IdentityManager.self) private var identity

  @State private var showRename = false
  @State private var editedName = ""
  @State private var showCopied = false
  @State private var qrImage: CGImage?

  var body: some View {
    ScrollView {
      VStack(spacing: 16) {
        Group {
          if let qrImage {
            Image(decorative: qrImage, scale: 1.0)
              .interpolation(.none)
              .resizable()
              .scaledToFit()
          } else {
            ProgressView()
          }
        }
        .frame(maxWidth: 280, maxHeight: 280)
        .padding()

        Button {
          editedName = session.myName
          showRename = true
        } label: {
          HStack(spacing: 6) {
            Text(session.myName).font(.title3.weight(.semibold))
            Image(systemName: "pencil").font(.footnote).foregroundStyle(.secondary)
          }
        }
        .buttonStyle(.plain)

        VStack(spacing: 4) {
          Text("Fingerprint").font(.headline)
          Button {
            Clipboard.copy(identity.publicKey.fingerprint)
            withAnimation { showCopied = true }
            Task {
              try? await Task.sleep(for: .seconds(1.5))
              withAnimation { showCopied = false }
            }
          } label: {
            Text(identity.publicKey.fingerprint)
              .font(.callout.monospaced())
              .multilineTextAlignment(.center)
              .padding(.horizontal)
          }
          .buttonStyle(.plain)
          Text("Tap to copy").font(.caption2).foregroundStyle(.secondary)
        }

        Text(
          "Have the other person scan this in Add Contact, then compare your safety numbers before trusting the chat."
        )
        .font(.footnote)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .padding(.horizontal)
      }
      .padding()
    }
    .navigationTitle("My Identity")
    .onAppear { regenerateQR() }
    .onChange(of: session.myName) { regenerateQR() }
    .overlay(alignment: .bottom) {
      if showCopied {
        Label("Copied to clipboard", systemImage: "checkmark.circle.fill")
          .font(.subheadline.weight(.medium))
          .padding(.horizontal, 14)
          .padding(.vertical, 9)
          .background(.green, in: Capsule())
          .foregroundStyle(.white)
          .padding(.bottom, 24)
          .transition(.move(edge: .bottom).combined(with: .opacity))
      }
    }
    .alert("Your Name", isPresented: $showRename) {
      TextField("Name", text: $editedName)
      Button("Cancel", role: .cancel) {}
      Button("Save") {
        let trimmed = editedName.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { session.setMyName(trimmed) }
      }
    } message: {
      Text("This name is shared in your QR code.")
    }
  }

  private func regenerateQR() {
    qrImage = QRCode.cgImage(from: session.myCard.encoded())
  }
}
