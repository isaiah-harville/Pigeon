//
//  RelayPinger.swift
//  Pigeon
//
//  Measures round-trip latency to relay endpoints for the settings UI, so users
//  can pick the closest one. It opens a throwaway WebSocket to each relay and
//  times a ping/pong; it sends no mailbox identifier and never authenticates, so
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
    case ms(Int)
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

  private func pingAll(_ urls: [URL]) async {
    await withTaskGroup(of: (URL, Ping).self) { group in
      for url in urls {
        group.addTask { (url, await Self.ping(url)) }
      }
      for await (url, result) in group {
        pings[url] = result
      }
    }
  }

  /// Opens a WebSocket and times a single ping/pong. The elapsed time includes
  /// the TCP+TLS+WS handshake on a fresh connection, which is the latency a user
  /// actually cares about when choosing a relay.
  nonisolated private static func ping(_ url: URL) async -> Ping {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 6
    config.waitsForConnectivity = false
    let session = URLSession(configuration: config)
    let socket = session.webSocketTask(with: url)
    let start = DispatchTime.now()
    socket.resume()
    let result: Ping = await withCheckedContinuation { continuation in
      socket.sendPing { error in
        if error != nil {
          continuation.resume(returning: .unreachable)
        } else {
          let ns = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
          continuation.resume(returning: .ms(Int(ns / 1_000_000)))
        }
      }
    }
    socket.cancel(with: .goingAway, reason: nil)
    session.invalidateAndCancel()
    return result
  }
}
