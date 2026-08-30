//
//  AddContactView.swift
//  Pigeon
//
//  Scan a nearby peer's QR card or import a shared contact link from anywhere.
//  The contact's name comes from their card; it can be edited later in the chat.
//

import PigeonFFI
import SwiftUI

struct AddContactView: View {
  @Environment(SessionManager.self) private var session
  @Environment(\.dismiss) private var dismiss

  @State private var pasted: String
  @State private var error: String?
  @State private var showManualEntry: Bool
  @State private var showingMyQR = false
  @State private var showingMyFingerprint = false
  @State private var addedName: String?
  /// Whether the contact we added arrived over a link rather than the camera. The
  /// other person isn't in the room, so telling them to scan our QR is useless —
  /// we point at the share link instead.
  @State private var addedRemotely = false
  /// Whether we presented our own code (QR or fingerprint) before scanning. If so
  /// the other person has already added us, so once we add them the exchange is
  /// complete — we don't flip back to our QR (we were the second to scan).
  @State private var didShowMyCode = false
  @State private var addedContactID: Data?
  @State private var canOfferMessageRequest = false

  private let onOpenMessageRequest: (Data) -> Void

  init() {
    self.init(initialCode: "") { _ in }
  }

  init(onOpenMessageRequest: @escaping (Data) -> Void) {
    self.init(initialCode: "", onOpenMessageRequest: onOpenMessageRequest)
  }

  /// Opened from a tapped contact link: prefill the code and open the panel it
  /// belongs to, so the user only has to confirm.
  init(initialCode: String) {
    self.init(initialCode: initialCode) { _ in }
  }

  init(initialCode: String, onOpenMessageRequest: @escaping (Data) -> Void) {
    _pasted = State(initialValue: initialCode)
    _showManualEntry = State(initialValue: !initialCode.isEmpty)
    self.onOpenMessageRequest = onOpenMessageRequest
  }

  /// Nothing more to do on the scanner: either the in-person exchange is mutual
  /// (we showed our code first, then added theirs), or we added a remote contact
  /// and the rest of the exchange happens over their channel, not the camera.
  private var isComplete: Bool { addedName != nil && (didShowMyCode || addedRemotely) }

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
      if addedRemotely {
        return "Added \(addedName). Send them your contact link so they can add you back."
      }
      return isComplete
        ? "Added \(addedName). You're all set."
        : "Have \(addedName) scan your QR, or send them a message request."
    }
    return showingMyQR
      ? "Have the other person scan this QR code to add you."
      : "Scan someone nearby, or exchange contact links if they're far away."
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
      if !isComplete { scanToggleButton }
      if canOfferMessageRequest, showingMyQR, let addedContactID {
        Button {
          guard session.beginMessageRequest(to: addedContactID) else {
            error = "Couldn't start a message request."
            return
          }
          onOpenMessageRequest(addedContactID)
        } label: {
          Label("Send Message Request", systemImage: "paperplane.fill")
        }
        .buttonStyle(.borderedProminent)
        .buttonBorderShape(.capsule)
      }
    }
  }

  private var scannerFrame: some View {
    ZStack {
      if isComplete {
        completionView
      } else if showingMyQR {
        myQRCode
      } else {
        QRScanner { code in handle(code, verifiedInPerson: true) }
        ScannerReticle()
      }
    }
    .aspectRatio(1, contentMode: .fit)
    .frame(maxWidth: 340)
    .background(showingMyQR || isComplete ? Color(.systemBackground) : .black)
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
        if showingMyQR { didShowMyCode = true }
      }
    } label: {
      Label(showingMyQR ? "Scan Contact QR" : "Show My QR", systemImage: "qrcode")
    }
    .buttonStyle(.bordered)
    .buttonBorderShape(.capsule)
  }

  private var completionView: some View {
    VStack(spacing: 16) {
      Image(systemName: "checkmark.circle.fill")
        .font(.system(size: 72))
        .foregroundStyle(.green)
      Text("Added \(addedName ?? "")")
        .font(.headline)
    }
  }

  private var myQRCode: some View {
    QRCode.image(from: session.myCard?.encoded() ?? "")
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
    showingMyFingerprint ? "My fingerprint" : "Add someone remotely"
  }

  private var manualEntryFields: some View {
    RemoteContactExchangeView(
      code: $pasted,
      myShareURL: session.myCard?.shareURL,
      onAdd: {
        // Shared codes arrive over an out-of-band channel, so the safety
        // number wasn't compared face to face — mark the contact unverified.
        handle(pasted, verifiedInPerson: false)
      },
      onShowFingerprint: {
        withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
          showingMyFingerprint = true
          didShowMyCode = true
        }
      }
    )
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
}

extension AddContactView {
  private func handle(_ code: String, verifiedInPerson: Bool) {
    guard let card = ContactCard(scanned: code) else {
      error = "That isn't a valid Pigeon contact code."
      return
    }
    let name = card.name.isEmpty ? "Unnamed" : card.name
    let wasAlreadyKnown = session.contacts.contains { $0.id == card.bundle.identityKey }
    if session.addContact(
      card.bundle, name: name, relayURLs: card.relayURLs,
      prekeyBundle: card.prekeyBundle,
      admission: verifiedInPerson ? .verifiedInPerson : .outgoingRequest)
    {
      error = nil
      pasted = ""
      // Mutual exchange: if we scanned them in person and hadn't already shown our
      // code, flip to our own QR so they can scan us back without leaving this
      // screen. If we *had* shown it first, they've already added us, so this
      // completes the exchange (see `isComplete`). A remote contact can't scan
      // anything, so we keep the link panel open for them to share back instead.
      withAnimation(.spring(response: 0.35, dampingFraction: 0.85)) {
        addedName = name
        addedContactID = card.bundle.identityKey
        canOfferMessageRequest = verifiedInPerson && !wasAlreadyKnown
        addedRemotely = !verifiedInPerson
        showingMyFingerprint = false
        showingMyQR = verifiedInPerson && !didShowMyCode
        if !verifiedInPerson { showManualEntry = true }
      }
    } else {
      error = "Couldn't add this contact (invalid binding, or it's your own code)."
    }
  }
}
