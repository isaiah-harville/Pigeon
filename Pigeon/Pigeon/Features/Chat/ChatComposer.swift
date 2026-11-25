//
//  ChatComposer.swift
//  Pigeon
//
//  Message composer and staged reply preview for ChatView.
//

import SwiftUI

struct ChatComposer: View {
  @Binding var draft: String
  @Binding var replyTarget: ChatMessage?
  var focus: FocusState<Bool>.Binding

  var enabled = true
  var disabledMessage: String?
  let onSend: (String, ChatMessage?) -> Void

  var body: some View {
    VStack(spacing: 6) {
      if let replyTarget {
        ReplyComposerPreview(message: replyTarget) {
          self.replyTarget = nil
        }
      }
      inputRow
      if !enabled, let disabledMessage {
        Text(disabledMessage)
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
      }
    }
    .padding()
  }

  private var inputRow: some View {
    HStack(spacing: 8) {
      TextField(enabled ? "Message" : "Waiting for acceptance", text: $draft, axis: .vertical)
        .focused(focus)
        .textFieldStyle(.plain)
        .lineLimit(1...4)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Capsule().fill(.fill.tertiary))
        .disabled(!enabled)
      sendButton
    }
  }

  /// The draft without surrounding whitespace; a blank draft cannot be sent.
  private var trimmedDraft: String {
    draft.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private var canSend: Bool { enabled && !trimmedDraft.isEmpty }

  private var sendButton: some View {
    Button {
      guard canSend else { return }
      onSend(trimmedDraft, replyTarget)
      draft = ""
      replyTarget = nil
    } label: {
      Image(systemName: "paperplane.fill")
        .font(.system(size: 15, weight: .semibold))
        .foregroundStyle(.white)
        .frame(width: 38, height: 38)
        .background(Capsule().fill(Color.accentColor))
        .frame(width: 44, height: 44)
        .contentShape(Rectangle())
    }
    .disabled(!canSend)
    .opacity(canSend ? 1 : 0.45)
    .accessibilityLabel("Send message")
  }
}

private struct ReplyComposerPreview: View {
  let message: ChatMessage
  let onDismiss: () -> Void

  var body: some View {
    HStack(spacing: 7) {
      RoundedRectangle(cornerRadius: 2, style: .continuous)
        .fill(Color.accentColor)
        .frame(width: 3, height: 16)
      Text("Replying")
        .font(.caption2.weight(.semibold))
        .foregroundStyle(.tint)
      Text(message.replySnippetText)
        .font(.caption2)
        .foregroundStyle(.secondary)
        .lineLimit(1)
      Spacer(minLength: 4)
      Button(action: onDismiss) {
        Image(systemName: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(width: 44, height: 44)
          .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .accessibilityLabel("Cancel reply")
      .padding(.vertical, -14)
    }
    .padding(.horizontal, 9)
    .padding(.vertical, 5)
    .background(
      .fill.quaternary,
      in: RoundedRectangle(cornerRadius: 8, style: .continuous)
    )
  }
}
