//
//  RelayPinger.swift
//  Pigeon
//
//  Measures round-trip latency to relay endpoints for the settings UI, so users
//  can pick the closest one. It opens a throwaway WebSocket to each relay and
//  negotiates protocol metadata; it sends no mailbox identifier and never authenticates, so
//  the relay learns nothing it wouldn't from any anonymous connection. Polling
//  runs only while the relay settings screen is open.
//

import Foundation

@MainActor
@Observable
final class RelayPinger {

  /// Latest measurement for each relay endpoint.
  enum Ping: Equatable {
    case measuring
    case available(milliseconds: Int, info: RelayTransport.RelayInfo)
    case unreachable
  }

  /// How often to re-measure while the screen is open.
  private static let pollInterval: TimeInterval = 20

  private(set) var pings: [URL: Ping] = [:]
  private var task: Task<Void, Never>?

  /// (Re)starts polling `urls`. A first round runs immediately; later rounds run
  /// every `pollInterval` seconds. Calling again replaces the previous schedule.
  func start(urls: [URL]) {
    stop()
    guard !urls.isEmpty else { return }
    for url in urls where pings[url] == nil { pings[url] = .measuring }
    task = Task { [weak self] in
      while !Task.isCancelled {
        await self?.pingAll(urls)
        try? await Task.sleep(for: .seconds(Self.pollInterval))
      }
    }
  }

  func stop() {
    task?.cancel()
    task = nil
  }

  nonisolated static func withTimeout<Value: Sendable>(
    _ duration: Duration,
    operation: @escaping @Sendable () async throws -> Value
  ) async throws -> Value {
    try await withThrowingTaskGroup(of: Value.self) { group in
      group.addTask { try await operation() }
      group.addTask {
        try await Task.sleep(for: duration)
        throw RelayError.timeout
      }
      defer { group.cancelAll() }
      guard let value = try await group.next() else { throw RelayError.timeout }
      return value
    }
  }

  private func pingAll(_ urls: [URL]) async {
    await withTaskGroup(of: (URL, Ping).self) { group in
      for url in urls {
        group.addTask { (url, await Self.probe(url)) }
      }
      for await (url, result) in group {
        pings[url] = result
      }
    }
  }

  /// Opens an anonymous WebSocket, negotiates the public protocol metadata, and
  /// measures the complete fresh-connection round trip. No mailbox is supplied.
  nonisolated static func probe(_ url: URL) async -> Ping {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 6
    config.waitsForConnectivity = false
    let session = URLSession(configuration: config)
    let socket = session.webSocketTask(with: url)
    defer {
      socket.cancel(with: .goingAway, reason: nil)
      session.invalidateAndCancel()
    }
    let start = DispatchTime.now()
    socket.resume()
    let result: Ping
    do {
      try await socket.send(RelayTransport.helloMessage())
      let response = try await Self.withTimeout(.seconds(6)) {
        try await withTaskCancellationHandler {
          try await socket.receive()
        } onCancel: {
          socket.cancel(with: .goingAway, reason: nil)
        }
      }
      let responseData: Data
      switch response {
      case .data(let data): responseData = data
      case .string(let text): responseData = Data(text.utf8)
      @unknown default: throw RelayError.protocolError
      }
      guard let object = try JSONSerialization.jsonObject(with: responseData) as? [String: Any],
        let info = RelayTransport.relayInfo(from: object)
      else { throw RelayError.protocolError }
      let ns = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
      result = .available(milliseconds: Int(ns / 1_000_000), info: info)
    } catch {
      result = .unreachable
    }
    return result
  }
}
