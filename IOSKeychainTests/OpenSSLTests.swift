//
//  OpenSSLTests.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//


import Foundation
import UIKit
import XCTest
import IOSKeychain

class OpenSSLCSRTests: XCTestCase {
    // Check that generateCSRWithPublicKeyData correctly returns an error
    func testCSRWithCorruptDataAndError() {
        var error: NSError?
        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        let attributes : [ NSObject : AnyObject] = [ : ]
        let csrData = OpenSSL.generateCSRWithKeyPair(keyPair, csrData: attributes, error: &error)
        XCTAssertNil(csrData)
        XCTAssertNotNil(error)
        XCTAssertEqual(error!.code, 9999)
        XCTAssertEqual(error!.localizedDescription,"Internal Error")
    }

    func testCSRWithCorruptDataAndNilError() {
        let attributes : [ NSObject : AnyObject] = [ : ]
        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        let csrData = OpenSSL.generateCSRWithKeyPair(keyPair,csrData: attributes, error: nil)
        XCTAssertNil(csrData)
    }

    func testGenerateCSR() {
        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)
        let keypairData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)
        let attributes : [ NSObject : AnyObject] = [ : ]

        XCTAssertNotNil(keypairData)
        let openSSLKeyPair = OpenSSL.keyPairFromPEMData(keypairData, encryptedWithPassword: "password", error: &error)

        XCTAssertNotNil(openSSLKeyPair)
        XCTAssertNotNil(openSSLKeyPair!.privateKeyData)
        XCTAssertNotNil(openSSLKeyPair!.publicKeyData)
        let csrData = OpenSSL.generateCSRWithKeyPair(openSSLKeyPair!,csrData: attributes, error: &error)

        XCTAssertNotNil(csrData)

        let csrString : NSString! = NSString(data: csrData!, encoding: NSUTF8StringEncoding)
        XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
        println("CSR:")
        println(csrString)
    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testGenerateCSRCorruptData() {
        var error: NSError?
        let attributes : [ NSObject : AnyObject] = [ : ]

        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        var csrData = OpenSSL.generateCSRWithKeyPair(keyPair,csrData: attributes, error: &error)

        XCTAssertNil(csrData)
        XCTAssertNotNil(error)
        XCTAssertEqual(error!.code, 9999)
        XCTAssertEqual(error!.localizedDescription,"Internal Error")

        error = nil
        csrData = OpenSSL.generateCSRWithKeyPair(keyPair,csrData: attributes, error: nil)
        XCTAssertNil(csrData)
    }
}

class OpenSSLKeyPairTests: XCTestCase {

    func testKeyPairFromPEM() {
        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)
        let pemFileData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)
        let attributes : [ NSObject : AnyObject] = [ : ]

        XCTAssertNotNil(pemFileData)
        let openSSLKeyPair = OpenSSL.keyPairFromPEMData(pemFileData, encryptedWithPassword: "password", error: &error)

        XCTAssertNotNil(openSSLKeyPair)
        XCTAssertNil(error)
    }


    func testKeyPairWrongPassphrase() {
        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)
        let pemFileData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)
        let attributes : [ NSObject : AnyObject] = [ : ]

        XCTAssertNotNil(pemFileData)
        let openSSLKeyPair = OpenSSL.keyPairFromPEMData(pemFileData, encryptedWithPassword: "wrongpassword", error: &error)

        XCTAssertNil(openSSLKeyPair)
        XCTAssertNotNil(error)
        XCTAssertEqual(error!.code, 9997)
        XCTAssertEqual(error!.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testKeyPairCorruptData() {
        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)
        let corruptPEMFileData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "p12")!)
        let attributes : [ NSObject : AnyObject] = [ : ]

        XCTAssertNotNil(corruptPEMFileData)
        let openSSLKeyPair = OpenSSL.keyPairFromPEMData(corruptPEMFileData, encryptedWithPassword: "wrongpassword", error: &error)

        XCTAssertNil(openSSLKeyPair)
        XCTAssertNotNil(error)
        XCTAssertEqual(error!.code, 9997)
        XCTAssertEqual(error!.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
    }
}



class OpenSSLIdentityTests: XCTestCase {
    func testIdentityFromX509File() {
        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)
        let keyPairPEMData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1 certificate", ofType: "x509")!)

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair = OpenSSL.keyPairFromPEMData(keyPairPEMData, encryptedWithPassword: "password", error: &error)

        XCTAssertNotNil(openSSLKeyPair)
        XCTAssertNil(error)

       var identity = OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair!, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "password", error: &error)

        XCTAssertNotNil(identity)
        XCTAssertNil(error)

        XCTAssertNotNil(identity!.p12identityData)
        XCTAssertEqual(identity!.friendlyName, "Expend Device ABCD")

    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testIdentityFromX509FileCorruptInputs() {
        var error: NSError?
        let bundle = NSBundle(forClass: self.dynamicType)
        let keyPairPEMData : NSData = NSData()

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData = NSData()

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())


        XCTAssertNotNil(openSSLKeyPair)
        XCTAssertNil(error)

        var identity = OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "password", error: &error)

        XCTAssertNil(identity)
        XCTAssertNotNil(error)

        XCTAssertEqual(error!.code, 9999)
        XCTAssertEqual(error!.localizedDescription,"Internal Error")
    }


}


