//
//  OpenSSLCertificate.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation


@objc public class OpenSSLCertificate : OpenSSLObject {
    @objc public private(set) var certificateData: NSData
    public init(certificateData: NSData) {
        self.certificateData = certificateData
        super.init()
    }
}

@objc public class OpenSSLCertificateSigningRequest : OpenSSLObject {
}



