import SwiftUI

/// Displayed only while both phones are unlocked and physically nearby.
struct IdentityMoveView: View {
  let mode: IdentityMoveCoordinator.Mode
  let sourceSession: SessionManager?
  let action: IdentityMoveAction

  @Environment(\.dismiss) private var dismiss
  @State private var coordinator: IdentityMoveCoordinator?
  @State private var setupError: String?

  var body: some View {
    NavigationStack {
      VStack(spacing: 20) {
        moveContent
        Spacer()
      }
      .padding()
      .navigationTitle(mode == .source ? "Move Pigeon" : "Receive Pigeon")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .cancellationAction) {
          Button("Close") {
            if coordinator?.phase == .finished {
              coordinator?.finish()
            } else {
              coordinator?.stop()
            }
            dismiss()
          }
          .disabled(coordinator?.phase == .retiring)
        }
      }
    }
    .task {
      guard coordinator == nil else { return }
      do {
        let move = try IdentityMoveCoordinator(
          mode: mode,
          sourceSession: sourceSession, action: action)
        coordinator = move
        move.start()
      } catch { setupError = "Pigeon could not prepare the local transfer." }
    }
    .interactiveDismissDisabled(coordinator?.phase == .retiring)
    .onDisappear { coordinator?.stop() }
  }

  @ViewBuilder
  private var moveContent: some View {
    if let coordinator {
      content(for: coordinator)
    } else if let setupError {
      Text(setupError).foregroundStyle(.red)
    } else {
      ProgressView()
    }
  }

  @ViewBuilder
  private func content(for move: IdentityMoveCoordinator) -> some View {
    switch move.phase {
    case .discovering:
      discoveryContent(for: move)
    case .compareCode(let code):
      codeContent(code, move: move)
    case .transferring:
      ProgressView("Transferring identity and live group state")
      Text("Saved messages are not copied.")
        .foregroundStyle(.secondary)
    case .staging:
      ProgressView("Securing state on this phone")
    case .retiring:
      ProgressView("Retiring the old phone")
      Text("Keep both phones open until the new phone confirms activation.")
        .multilineTextAlignment(.center)
    case .finished:
      finishedContent(for: move)
    case .failed(let message):
      Image(systemName: "exclamationmark.shield")
        .font(.system(size: 48))
        .foregroundStyle(.red)
      Text(message).multilineTextAlignment(.center)
    }
  }

  @ViewBuilder
  private func discoveryContent(for move: IdentityMoveCoordinator) -> some View {
    if mode == .source {
      Image(systemName: "iphone.gen3.radiowaves.left.and.right")
        .font(.system(size: 52))
      Text("On your new phone, choose Receive Pigeon. Keep both phones unlocked and nearby.")
        .multilineTextAlignment(.center)
      ProgressView("Waiting for new phone")
    } else {
      Text("Select your old phone. Check that the same code appears on both screens.")
        .multilineTextAlignment(.center)
      ForEach(move.peers, id: \.self) { peer in
        Button(peer) { move.connect(to: peer) }
          .buttonStyle(.borderedProminent)
      }
      if move.peers.isEmpty { ProgressView("Looking for old phone") }
    }
  }

  @ViewBuilder
  private func codeContent(_ code: String, move: IdentityMoveCoordinator) -> some View {
    Text("Compare this code on both phones")
      .font(.headline)
    Text(code)
      .font(.system(.largeTitle, design: .monospaced).weight(.bold))
      .textSelection(.disabled)
    Text("Continue only if every digit matches. Keep both phones unlocked.")
      .multilineTextAlignment(.center)
    Button("Codes match") { move.confirmCode() }
      .buttonStyle(.borderedProminent)
  }

  @ViewBuilder
  private func finishedContent(for move: IdentityMoveCoordinator) -> some View {
    Image(systemName: "checkmark.shield.fill")
      .font(.system(size: 52))
      .foregroundStyle(.green)
    Text(
      mode == .source
        ? "Move complete. This phone has a new identity."
        : "Identity and group membership moved to this phone."
    )
    .multilineTextAlignment(.center)
    Button("Done") {
      move.finish()
      dismiss()
    }
    .buttonStyle(.borderedProminent)
  }
}
