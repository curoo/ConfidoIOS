//
//  KeyPairTests.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import UIKit
import XCTest
import IOSKeychain

class KeyPairTests: XCTestCase {
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    func testGenerateNamedKeyPair() {
        clearKeychainItems()
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, .OK)
        XCTAssertEqual(count(items),0)

        let keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 1024, keyLabel: "AAA", keyAppTag: "BBB", keyAppLabel: "CCC")
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, .OK)
        XCTAssertNotNil(keyPair)

        (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(count(items),2)

        let keySpecifier = KeySpecifier(keyLabel: "AAA")
        var keyItem: KeychainItem?
        (status, keyItem) = Keychain.fetchMatchingItem(itemSpecifier: keySpecifier)
        XCTAssertEqual(status, .OK)
        XCTAssertNotNil(keyItem)
        XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair!.publicKey.keySize, 1024)

        XCTAssertNotNil(keyPair!.privateKey.itemLabel)
        XCTAssertEqual(keyPair!.privateKey.itemLabel!, "AAA")

        XCTAssertNotNil(keyPair!.privateKey.keyAppTag)
        XCTAssertEqual(keyPair!.privateKey.keyAppTag!, "BBB")

        XCTAssertNotNil(keyPair!.privateKey.keyAppLabel)
        XCTAssertEqual(keyPair!.privateKey.keyAppLabel!, "CCC")

        let publicKeyData = keyPair!.publicKey.keyData
        XCTAssertNotNil(publicKeyData)

        let privateKeyData = keyPair!.privateKey.keyData
        XCTAssertNotNil(privateKeyData)

        XCTAssertEqual(publicKeyData!.length,140)
        XCTAssert(privateKeyData!.length > 0)

    }

    func testGenerateUnnamedKeyPair() {
        clearKeychainItems()
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, .OK)
        XCTAssertEqual(count(items),0)

        let keyPairSpecifier = TemporaryKeyPairSpecification(keyType: .RSA, keySize: 1024)
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, .OK)
        XCTAssertNotNil(keyPair)

        (status, items) = Keychain.keyChainItems(.Key)
        // Temporary keys are not stored in the keychain
        XCTAssertEqual(count(items),0)

        XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair!.publicKey.keySize, 1024)


        // There is no way to extract the data of a key for non-permanent keys
        let publicKeyData = keyPair!.publicKey.keyData
        XCTAssertNil(publicKeyData)

        let privateKeyData = keyPair!.privateKey.keyData
        XCTAssertNil(privateKeyData)

    }


    func testDuplicateKeyPairMatching() {
        clearKeychainItems()
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, .OK)
        XCTAssertEqual(count(items),0)

        var keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 1024, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, .OK)
        XCTAssertNotNil(keyPair)


        (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(count(items),2)

        // Test that labels make the keypair unique
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)

        // keySize, keyLabel, keyAppTag, keyAppLabel all the same --> DuplicateItemError
        XCTAssertEqual(status, .DuplicateItemError)
        XCTAssertNil(keyPair)

        // different keySize
        keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 2048, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, .OK)
        XCTAssertNotNil(keyPair)


    }

    func clearKeychainItems() {
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, .OK)

        var n = count(items)
        for item in items {
            status = Keychain.deleteKeyChainItem(itemSpecifier: item.specifier())
            XCTAssertEqual(status, .OK)

            (status, items) = Keychain.keyChainItems(.Key)
            XCTAssertEqual(status, .OK)

            XCTAssertEqual(count(items),n-1)
            n = count(items)
        }
        XCTAssertEqual(count(items),0)
    }

}
