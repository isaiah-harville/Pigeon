//
//  PrimitivesTests.swift
//  PigeonCryptoTests
//

import XCTest
import Foundation
import CryptoKit
@testable import PigeonCrypto

final class PrimitivesTests: XCTestCase {

    // MARK: - DH

    func testDHSymmetry() throws {
        let alice = DHKeyPair()
        let bob = DHKeyPair()
        let ab = try alice.sharedSecret(with: bob.publicKey)
        let ba = try bob.sharedSecret(with: alice.publicKey)
        XCTAssertEqual(ab, ba)
        XCTAssertEqual(ab.count, 32)
    }

    // MARK: - KDF_RK

    func testRootKDFDeterministicAndSplit() {
        let rk = Data(repeating: 0x11, count: 32)
        let dh = Data(repeating: 0x22, count: 32)

        let first = Primitives.kdfRootKey(rootKey: rk, dhOutput: dh)
        let again = Primitives.kdfRootKey(rootKey: rk, dhOutput: dh)

        XCTAssertEqual(first.rootKey, again.rootKey)   // deterministic
        XCTAssertEqual(first.chainKey, again.chainKey)
        XCTAssertEqual(first.rootKey.count, 32)
        XCTAssertEqual(first.chainKey.count, 32)
        XCTAssertNotEqual(first.rootKey, first.chainKey) // halves differ

        let other = Primitives.kdfRootKey(rootKey: rk, dhOutput: Data(repeating: 0x33, count: 32))
        XCTAssertNotEqual(other.rootKey, first.rootKey)  // input-dependent
    }

    // MARK: - KDF_CK

    func testChainKDFAdvances() {
        let ck0 = Data(repeating: 0xAB, count: 32)
        let step1 = Primitives.kdfChainKey(chainKey: ck0)
        let step2 = Primitives.kdfChainKey(chainKey: step1.chainKey)

        XCTAssertNotEqual(step1.chainKey, ck0)
        XCTAssertNotEqual(step1.messageKey, step1.chainKey)
        XCTAssertNotEqual(step1.messageKey, step2.messageKey)
        XCTAssertNotEqual(step1.chainKey, step2.chainKey)
        XCTAssertEqual(step1.messageKey.count, 32)
    }

    // MARK: - AEAD

    func testAEADRoundTrip() throws {
        let mk = Data(repeating: 0x7E, count: 32)
        let plaintext = Data("the eagle lands at dawn".utf8)
        let ad = Data("ratchet-header".utf8)

        let ct = try Primitives.encrypt(plaintext: plaintext, messageKey: mk, associatedData: ad)
        let pt = try Primitives.decrypt(ciphertext: ct, messageKey: mk, associatedData: ad)
        XCTAssertEqual(pt, plaintext)
        XCTAssertNotEqual(ct, plaintext)
    }

    func testAEADTamperDetection() throws {
        let mk = Data(repeating: 0x7E, count: 32)
        let ad = Data("header".utf8)
        var ct = try Primitives.encrypt(plaintext: Data("hello".utf8), messageKey: mk, associatedData: ad)
        ct[ct.startIndex] ^= 0xFF // flip a bit

        XCTAssertThrowsError(try Primitives.decrypt(ciphertext: ct, messageKey: mk, associatedData: ad)) {
            XCTAssertEqual($0 as? CryptoError, .authenticationFailed)
        }
    }

    func testAEADAssociatedDataBinding() throws {
        let mk = Data(repeating: 0x7E, count: 32)
        let ct = try Primitives.encrypt(plaintext: Data("hi".utf8), messageKey: mk, associatedData: Data("A".utf8))

        XCTAssertThrowsError(try Primitives.decrypt(ciphertext: ct, messageKey: mk, associatedData: Data("B".utf8))) {
            XCTAssertEqual($0 as? CryptoError, .authenticationFailed)
        }
    }

    func testAEADInvalidKeyLength() {
        XCTAssertThrowsError(try Primitives.encrypt(plaintext: Data("x".utf8), messageKey: Data([0x00]), associatedData: Data())) {
            XCTAssertEqual($0 as? CryptoError, .invalidLength)
        }
    }
}
