//
//  IdentityQRView.swift
//  Pigeon
//
//  Shows this device's identity as a QR code for a peer to scan in person.
//  Tap your name to edit it (the QR regenerates); tap the fingerprint to copy.
//

import SwiftUI
import UIKit

struct IdentityQRView: View {
  @Environment(SessionManager.self) private var session
  @Environment(IdentityManager.self) private var identity

  @State private var showRename = false
  @State private var editedName = ""
  @State private var showCopied = false
  @State private var qrImage: CGImage?
  @State private var priorBrightness: CGFloat = 1.0

  var body: some View {
    content
      .navigationTitle("My Identity")
      .onAppear {
        if let screen = activeScreen {
          priorBrightness = screen.brightness
          screen.brightness = 1.0  // max brightness so the QR scans reliably
        }
        regenerateQR()
      }
      .onDisappear { activeScreen?.brightness = priorBrightness }
      .onChange(of: session.myName) { regenerateQR() }
      .onChange(of: session.relayURLs) { regenerateQR() }  // advertised relays changed
      .overlay(alignment: .bottom) { copiedToast }
      .alert("Your Name", isPresented: $showRename) {
        TextField("Name", text: $editedName)
        Button("Cancel", role: .cancel) {}
        Button("Save") { saveName() }
      } message: {
        Text("This name is shared in your QR code.")
      }
  }

  private var content: some View {
    ScrollView {
      VStack(spacing: 16) {
        qrCodeImage
        nameButton
        fingerprintBlock
        trustHint
      }
      .padding()
    }
  }

  @ViewBuilder
  private var qrCodeImage: some View {
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
  }

  private var nameButton: some View {
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
  }

  private var fingerprintBlock: some View {
    VStack(spacing: 4) {
      Text("Fingerprint").font(.headline)
      Button {
        copyFingerprint()
      } label: {
        Text(identity.publicKey.fingerprint)
          .font(.callout.monospaced())
          .multilineTextAlignment(.center)
          .padding(.horizontal)
      }
      .buttonStyle(.plain)
      Text("Tap to copy").font(.caption2).foregroundStyle(.secondary)
    }
  }

  private var trustHint: some View {
    Text(trustHintText)
      .font(.footnote)
      .foregroundStyle(.secondary)
      .multilineTextAlignment(.center)
      .padding(.horizontal)
  }

  private var trustHintText: String {
    """
    Have the other person scan this in Add Contact, then compare your safety \
    numbers before trusting the chat.
    """
  }

  @ViewBuilder
  private var copiedToast: some View {
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

  private func copyFingerprint() {
    Clipboard.copy(identity.publicKey.fingerprint)
    withAnimation { showCopied = true }
    Task {
      try? await Task.sleep(for: .seconds(1.5))
      withAnimation { showCopied = false }
    }
  }

  private func saveName() {
    let trimmed = editedName.trimmingCharacters(in: .whitespacesAndNewlines)
    if !trimmed.isEmpty { session.setMyName(trimmed) }
  }

  private func regenerateQR() {
    qrImage = QRCode.cgImage(from: session.myCard.encoded())
  }

  /// The foreground scene's screen, used to adjust brightness. Replaces the
  /// deprecated `UIScreen.main` with the per-window-scene screen (iOS 26+).
  private var activeScreen: UIScreen? {
    UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .first { $0.activationState == .foregroundActive }?
      .screen
  }
}
