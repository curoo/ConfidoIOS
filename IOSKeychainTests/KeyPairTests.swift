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

    func testGenerateNamedKeyPair() {
        clearKeychainItems(.Key)
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
        clearKeychainItems(.Key)
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
        clearKeychainItems(.Key)
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



    func testExportCSR (){
        clearKeychainItems(.Key)
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, .OK)
        XCTAssertEqual(count(items),0)

        var keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 1024, keyLabel: "KeyPair1")
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, .OK)
        XCTAssertNotNil(keyPair)

        let attributes = [
            "UID" : "Test Device",
            "CN" : "Expend Device ABCD" ]

        let csr : NSData! = keyPair?.certificateSigningRequest(attributes)
        XCTAssertNotNil(csr)
        let csrString : NSString! = NSString(data: csr, encoding: NSUTF8StringEncoding)
        XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
        println("CSR:")
        println(csrString)
    }


    func testImportIdentity() {

        clearKeychainItems(.Identity)
        clearKeychainItems(.Key)
        clearKeychainItems(.Certificate)

        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)

        let keyPairPEMData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1 certificate", ofType: "x509")!)

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair = OpenSSL.keyPairFromPEMData(keyPairPEMData, encryptedWithPassword: "password", error: &error)

        XCTAssertNotNil(openSSLKeyPair)
        XCTAssertNil(error)

        var openSSLIdentity = OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair!, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "randompassword", error: &error)


        XCTAssertNotNil(openSSLIdentity)
        XCTAssertNil(error)

        let p12Identity = P12Identity(openSSLIdentity: openSSLIdentity!, importPassphrase: "randompassword")


        let ref = Keychain.importP12Identity(p12Identity)
        XCTAssertNotNil(ref)

        let specifier = IdentityImportSpecifier(identityReference: ref!, itemLabel: "SomeLabel")
        Keychain.addIdentity(specifier)
    }



    func clearKeychainItems(type: SecurityClass) {
        var (status, items) = Keychain.keyChainItems(type)
        XCTAssertEqual(status, .OK)

        var n = count(items)
        for item in items {
            status = Keychain.deleteKeyChainItem(itemSpecifier: item.specifier())
            XCTAssertEqual(status, .OK)

            (status, items) = Keychain.keyChainItems(type)
            XCTAssertEqual(status, .OK)

            XCTAssertEqual(count(items),n-1)
            n = count(items)
        }
        XCTAssertEqual(count(items),0)
    }





}
