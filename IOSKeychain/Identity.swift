//
//  Identity.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation
import Security


public class IdentityReference {
    public let secItemRef : SecIdentityRef
    public init(reference: SecIdentityRef) {
        self.secItemRef = reference
    }
}

public class IdentitySpecifier : KeychainItemSpecifier, KeychainQuery {
    public init(keySpecifier: KeySpecifier) {
        super.init(itemSpecifier: keySpecifier)
    }

    public init(itemLabel: String) {
            super.init(securityClass: .Identity, itemLabel: itemLabel)
    }

    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }
}

public class IdentityImportSpecifier : KeychainItemSpecifier, KeychainQuery {

    public init(identityReference: IdentityReference, itemLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .Identity, itemLabel: nil)
            if keyAppLabel != nil {
                attributes[String(kSecAttrApplicationLabel)] = KeySpecifier.encodeKeyAppLabel(keyAppLabel)
            }
            if keyAppTag != nil {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag!
            }
        attributes[String(kSecValueRef)] = identityReference.secItemRef
    }
}



public class P12Identity {
    let openSSLIdentity : OpenSSLIdentity
    public let importPassphrase : String
    public init(openSSLIdentity identity: OpenSSLIdentity, importPassphrase: String) {
        self.openSSLIdentity = identity
        self.importPassphrase = importPassphrase
    }

    public var p12EncodedIdentityData: NSData {
        get { return openSSLIdentity.p12identityData }
    }
}

public class Identity : KeyPair {

}