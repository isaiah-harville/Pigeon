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

  let onSend: (String, ChatMessage?) -> Void

  var body: some View {
    VStack(spacing: 6) {
      if let replyTarget {
        ReplyComposerPreview(message: replyTarget) {
          self.replyTarget = nil
        }
      }
      inputRow
    }
    .padding()
  }

  private var inputRow: some View {
    HStack(spacing: 8) {
      TextField("Message", text: $draft, axis: .vertical)
        .textFieldStyle(.plain)
        .lineLimit(1...4)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Capsule().fill(.fill.tertiary))
      sendButton
    }
  }

  private var sendButton: some View {
    Button {
      onSend(draft, replyTarget)
      draft = ""
      replyTarget = nil
    } label: {
      Image(systemName: "paperplane.fill")
        .font(.system(size: 15, weight: .semibold))
        .foregroundStyle(.white)
        .frame(width: 38, height: 38)
        .background(Capsule().fill(Color.accentColor))
    }
    .disabled(draft.isEmpty)
    .opacity(draft.isEmpty ? 0.45 : 1)
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
      }
      .buttonStyle(.plain)
    }
    .padding(.horizontal, 9)
    .padding(.vertical, 5)
    .background(
      .fill.quaternary,
      in: RoundedRectangle(cornerRadius: 8, style: .continuous)
    )
  }
}
