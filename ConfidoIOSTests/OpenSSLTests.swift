//
//  OpenSSLTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//


import Foundation
import UIKit
import XCTest
import ConfidoIOS
class OpenSSLCSRTests: BaseTests {
    // Check that generateCSRWithPublicKeyData correctly returns an error
    func testCSRWithCorruptDataAndError() {
        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        let attributes : [ NSObject : AnyObject] = [ : ]
        do {
            _ = try OpenSSL.generateCSRWithPrivateKeyData(keyPair.privateKeyData, csrData: attributes)
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }
    }

    func testCSRWithCorruptDataAndNilError() {
        do {
            let attributes : [ NSObject : AnyObject] = [ : ]
            let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
            _ = try OpenSSL.generateCSRWithPrivateKeyData(keyPair.privateKeyData, csrData: attributes)
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }
    }

    func testGenerateCSR() {
        do {
            let keypairData = try contentsOfBundleResource("test keypair 1", ofType: "pem")
            let attributes : [ NSObject : AnyObject] = [ : ]

            XCTAssertNotNil(keypairData)
            let openSSLKeyPair: OpenSSLKeyPair?
            openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keypairData, encryptedWithPassword: "password")
            XCTAssertNotNil(openSSLKeyPair)
            XCTAssertNotNil(openSSLKeyPair!.privateKeyData)
            XCTAssertNotNil(openSSLKeyPair!.publicKeyData)
            let csrData = try OpenSSL.generateCSRWithPrivateKeyData(openSSLKeyPair!.privateKeyData,csrData: attributes)
            XCTAssertNotNil(csrData)
            let csrString : NSString! = NSString(data: csrData, encoding: NSUTF8StringEncoding)
            XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
            XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
            print("CSR:")
            print(csrString)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testGenerateCSRCorruptData() {
        let attributes : [ NSObject : AnyObject] = [ : ]

        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        do {
            _ = try OpenSSL.generateCSRWithPrivateKeyData(keyPair.privateKeyData,csrData: attributes)
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }

        let csrData = try? OpenSSL.generateCSRWithPrivateKeyData(keyPair.privateKeyData,csrData: attributes)
        XCTAssertNil(csrData)
    }
}

class OpenSSLKeyPairTests: BaseTests {

    func testKeyPairFromPEM() {
        do {
            let pemFileData = try contentsOfBundleResource("test keypair 1", ofType: "pem")

            let openSSLKeyPair: OpenSSLKeyPair?
            openSSLKeyPair = try OpenSSL.keyPairFromPEMData(pemFileData, encryptedWithPassword: "password")
            XCTAssertNotNil(openSSLKeyPair)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testKeyPairWrongPassphrase() {
        do {
            let pemFileData = try contentsOfBundleResource("test keypair 1", ofType: "pem")
            _ = try OpenSSL.keyPairFromPEMData(pemFileData, encryptedWithPassword: "wrongpassword")
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9997)
            XCTAssertEqual(error.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
        }

    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testKeyPairCorruptData() {

        do {
            //Load a P12 file, this is not a PEM, so it will be corrupt.
            let corruptPEMFileData = try contentsOfBundleResource("Device Identity", ofType: "p12")
            XCTAssertNotNil(corruptPEMFileData)
            _ = try OpenSSL.keyPairFromPEMData(corruptPEMFileData, encryptedWithPassword: "wrongpassword")
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9997)
            XCTAssertEqual(error.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
        }
    }
}



class OpenSSLIdentityTests: BaseTests {
    func testIdentityFromX509File() {
        do {
        let keyPairPEMData = try contentsOfBundleResource("test keypair 1", ofType: "pem")

        let certificateData = try contentsOfBundleResource("test keypair 1 certificate", ofType: "x509")

        XCTAssertNotNil(certificateData)


            let openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keyPairPEMData, encryptedWithPassword: "password")

            XCTAssertNotNil(openSSLKeyPair)

            let identity = try OpenSSL.pkcs12IdentityWithPrivateKeyData(openSSLKeyPair.privateKeyData, certificateData: certificateData, protectedWithPassphrase: "password")


            XCTAssertNotNil(identity)

            XCTAssertNotNil(identity.p12identityData)
            XCTAssertEqual(identity.friendlyName, "Expend Device ABCD")
        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testIdentityFromX509FileCorruptInputs() {
        let keyPairPEMData : NSData = NSData()

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData = NSData()

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())


        XCTAssertNotNil(openSSLKeyPair)
        do {
            _ = try OpenSSL.pkcs12IdentityWithPrivateKeyData(openSSLKeyPair.privateKeyData, certificateData: certificateData, protectedWithPassphrase: "password")
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }

    }


}


