//
//  OpenSSLCertificate.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
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



