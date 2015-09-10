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
import IOSKeychain

class CertificateTests: XCTestCase {

    func testCertificateFromCERFile() {

        let bundle = NSBundle(forClass: self.dynamicType)

        let certificateDERData : NSData! = NSData(contentsOfFile: bundle.pathForResource("Curoo Root CA", ofType: "cer")!)

        let certificate : Certificate! = Certificate.certificate(certificateDERData)
        XCTAssertNotNil(certificate)
        XCTAssertEqual(certificate.subject!, "Curoo Limited Certification Authority")


    }
}