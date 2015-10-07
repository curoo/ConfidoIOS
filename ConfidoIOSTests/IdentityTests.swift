//
//  IdentityTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 14/09/2015.

import Foundation

import UIKit
import XCTest
import ConfidoIOS

class IdentityTests: BaseTests {
    func addCertificateToKeychain(certificateName: String) throws -> KeychainCertificate {
        let certificateDERData = try contentsOfBundleResource(certificateName, ofType: "cer")
        let transportCertificate = try KeychainCertificate.certificate(certificateDERData)
        return try transportCertificate.addToKeychain()
    }


    func testImportPKCS12Identity() {
        do {
            //TODO: Need a proper
            clearKeychainItems(.Identity)
            clearKeychainItems(.Key)
            clearKeychainItems(.Certificate)
            try addCertificateToKeychain("Curoo Root CA" )
            try addCertificateToKeychain("Curoo Product CA")
            try addCertificateToKeychain("Expend CA")
            try addCertificateToKeychain("Expend Device CA")
            XCTAssertEqual(self.keychainItems(.Certificate).count, 4)

            let p12Data = try contentsOfBundleResource("Device Identity", ofType: "p12")

            let transportIdentity = try KeychainIdentity.importIdentity(p12Data, protectedWithPassphrase: "password", label: "identity")
            _ = try transportIdentity.addToKeychain()

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
        
    }
    
}