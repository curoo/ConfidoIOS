//
//  CertificateTests.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

import UIKit
import XCTest
import ConfidoIOS

let customCACertName  = "Curoo Limited Certification Authority RSA Root Certificate"
let levelOneCAName    = "Curoo Limited Product Development Authority RSA Root Certificate"
let levelTwoCAName    = "Expend Product Development Authority RSA Root Certificate"
let finalPinnedCAName = "Expend Development Device Identity Authority RSA Certificate"

//TODO: Lock the evaluation date to... today to prevent future failures
//TODO: TrustEvaluationPoints (TrustManager)

class CertificateTests: BaseTests {

    func rootAnchor() throws -> TrustAnchor  {
        let rootCertificate = try bundledCertificate(customCACertName)
        return TrustAnchor(anchorCertificate: rootCertificate, name: "RootCA")
    }

    func level1CustomCA() throws -> TrustAnchor {
        let certificate = try bundledCertificate(levelOneCAName)
        let parentAnchor = try rootAnchor()
        return try parentAnchor.extendAnchor(certificate, name: "Level 1 CA")
    }

    func level2CustomCA() throws -> TrustAnchor {
        let certificate = try bundledCertificate(levelTwoCAName)
        let parentAnchor = try level1CustomCA()

        return try parentAnchor.extendAnchor(certificate, name: "Level 2 CA")
    }

    func level3IssuerCA() throws -> TrustAnchor {
        return try level2CustomCA().extendAnchor(
            try bundledCertificate(finalPinnedCAName),
            name: "Issuing CA")
    }

    func appleCert() throws -> Certificate {
        return try bundledCertificate("www.apple.com")
    }

    func symantecRealCert() throws -> Certificate {
        return try bundledCertificate("Symantec Class 3 EV SSL CA - G3")
    }

    func googleRealCACert() throws -> Certificate {
        return try bundledCertificate("Google Internet Authority G2")
    }

    func googleCAAnchor() throws -> TrustAnchor {
        return try TrustAnchor(anchorCertificate: googleRealCACert(), name: "Google CA")
    }

    func googleCert() throws -> Certificate {
        return try bundledCertificate("www.google.co.uk")
    }

    func customPinnedAnchorOnly() throws -> TrustAnchor {
        return TrustAnchor(anchorCertificate: try bundledCertificate(finalPinnedCAName))
    }


    func testCertificateFromCERFile() {
        do {
            self.clearKeychainItems(.Certificate)
            let certificateDERData = try contentsOfBundleResource(finalPinnedCAName, ofType: "cer")
            let transportCertificate = try KeychainCertificate.certificate(certificateDERData)
            XCTAssertEqual(transportCertificate.subject, finalPinnedCAName)

            let certificate = try transportCertificate.addToKeychain()
            XCTAssertEqual(certificate.subject, finalPinnedCAName)
            XCTAssertNotNil(certificate.secCertificate)
            XCTAssertEqual(self.keychainItems(.Certificate).count,1)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func bundledCertificate(filename: String) throws -> TransportCertificate {
        let certificateDERData = try contentsOfBundleResource(filename, ofType: "cer")
        return try KeychainCertificate.certificate(certificateDERData)
    }

    func testCertificateTrustAnchorChain()  {
        do {

            let rootCAAnchor   = try rootAnchor()
            XCTAssertEqual(rootCAAnchor.certificateChain.count, 1)

            let level1CAAnchor = try level1CustomCA()
            XCTAssertEqual(level1CAAnchor.certificateChain.count, 2)

            let level2CAAnchor = try level2CustomCA()
            XCTAssertEqual(level2CAAnchor.certificateChain.count, 3)

            let level3CAAnchor = try level3IssuerCA()
            XCTAssertEqual(level3CAAnchor.certificateChain.count, 4)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }

    }

    func testEvaluateTrustForClientCertificate()  {
        do {
            self.clearKeychainItems(.Certificate)

            let p12Data = try contentsOfBundleResource("Device Identity", ofType: "p12")
            let transportIdentity = try KeychainIdentity.importIdentity(p12Data, protectedWithPassphrase: "password", label: "identity")
            let trustPoint = try CertificateTrustPoint(secTrust: transportIdentity.secTrust)

            //Evaluate against the Root CA, with missing intermediaries
            var result = try trustPoint.evaluateTrust(rootAnchor())
            XCTAssertEqual(result, TrustResult.Deny)

            //Evaluate against the Issuer
            result = try trustPoint.evaluateTrust(level3IssuerCA())
            XCTAssertEqual(result, TrustResult.Unspecified)
            
            
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testEvaluateTrustForClientCertificatePinnedAtRoot() {
        do {
            let deviceCert = try bundledCertificate("test keypair 1 certificate")

            let trustNoAdditionalCerts = try deviceCert.trustPoint(.SSLClient(name: nil), additionalCertificates:[] )
            let trustAllCerts          = try deviceCert.trustPoint(.SSLClient(name: nil),
                additionalCertificates:[
                    level3IssuerCA().anchorCertificate,
                    level2CustomCA().anchorCertificate,
                    level1CustomCA().anchorCertificate
                ] )

            var result = try trustNoAdditionalCerts.evaluateTrust(rootAnchor())
            XCTAssertEqual(result, TrustResult.Deny)

            result = try trustAllCerts.evaluateTrust(rootAnchor())
            XCTAssertEqual(result, TrustResult.Unspecified)


        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testRealCertificateAgainstCustomRootCAAnchor() {
        do {
            /*
            Tests that the policies reject a real certificate (valid under ordinary circumstances) against a pinned anchor
            */
            let trust = try appleCert().trustPoint(TrustPolicy.SSLServer(hostname: nil),
                additionalCertificates: [symantecRealCert()])

            var result = try trust.evaluateTrust() // This should be allowed because we are checking a real certificate
            XCTAssertEqual(result, TrustResult.Unspecified)

            result = try trust.evaluateTrust(rootAnchor())
            XCTAssertEqual(result, TrustResult.Deny)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }


    func testRealCertificateAgainstDifferentRootCAAnchor() {
        do {
            /*
            Tests that the policies reject a real certificate (valid under ordinary circumstances) against a pinned anchor (also real)
            */
            let trust = try appleCert().trustPoint(TrustPolicy.SSLServer(hostname: nil),
                additionalCertificates: [symantecRealCert()])
            let result = try trust.evaluateTrust(googleCAAnchor())
            XCTAssertEqual(result, TrustResult.Deny)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }


    func testRealCertificateChainAnchored() {
        do {
            let trust = try googleCert().trustPoint(TrustPolicy.SSLServer(hostname: nil),
                additionalCertificates: [])

            let result = try trust.evaluateTrust(googleCAAnchor())
            XCTAssertEqual(result, TrustResult.Unspecified)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

}