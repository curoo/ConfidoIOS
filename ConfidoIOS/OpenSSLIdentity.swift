//
//  OpenSSLIdentity.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//

import Foundation


@objc public class OpenSSLIdentity : OpenSSLObject {
    @objc public private(set) var p12identityData: NSData
    @objc public private(set) var friendlyName: String

    public init(p12EncodedIdentityData data: NSData, friendlyName name: String) {
        self.p12identityData = data
        self.friendlyName = name
        super.init()
    }

}
