//
//  RelayDepositQueue.swift
//  Pigeon
//
//  Send-side store-and-forward for the relay transport: a bounded FIFO of
//  outbound deposits that found no ready relay, held for re-send the instant a
//  usable link comes up. Pure and value-typed so the queue/flush policy is
//  unit-tested without live sockets — the transport supplies a closure that
//  actually tries to publish.
//

import Foundation

extension RelayTransport {

  /// A bounded FIFO of deposits awaiting a ready relay.
  struct DepositQueue: Equatable {
    /// One queued outbound deposit: opaque ciphertext and its recipient, kept so
    /// the target relays can be re-resolved at flush time (the recipient's
    /// advertised/preferred relays may have changed since it was queued).
    struct Deposit: Equatable {
      let requestID: String
      let recipient: Data
      let message: Data
    }

    private let bound: Int
    private(set) var deposits: [Deposit] = []

    init(bound: Int) { self.bound = max(1, bound) }

    var isEmpty: Bool { deposits.isEmpty }
    var count: Int { deposits.count }

    /// Appends a deposit, evicting the oldest once the bound is exceeded so an
    /// unreachable recipient can't grow the queue without limit.
    mutating func enqueue(_ deposit: Deposit) {
      deposits.append(deposit)
      if deposits.count > bound {
        deposits.removeFirst(deposits.count - bound)
      }
    }

    /// Removes only a deposit confirmed by the relay. The server-assigned
    /// envelope ID is distinct from our request ID.
    @discardableResult
    mutating func acknowledge(requestID: String) -> Bool {
      guard let index = deposits.firstIndex(where: { $0.requestID == requestID }) else {
        return false
      }
      deposits.remove(at: index)
      return true
    }

    /// Re-attempts each queued deposit in FIFO order. A socket write alone
    /// never removes one; only `acknowledge` does.
    mutating func flush(_ send: (Deposit) -> Bool) {
      for deposit in deposits { _ = send(deposit) }
    }
  }
}
