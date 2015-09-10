//
//  ItemSpecifier.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

public protocol KeychainQuery {
    func keychainQuery() -> [ String: AnyObject ]
    var securityClass: SecurityClass { get }
}

public class KeychainItemSpecifier : KeychainItem, KeychainQuery {
    public init(keychainItem: KeychainItem) {
        super.init(securityClass: keychainItem.securityClass)
        for matchingProperty in keychainItem.specifierMatchingProperties() {
            if let value: AnyObject = keychainItem[matchingProperty] {
                attributes[matchingProperty] = value
            }
        }
    }

    public init(itemSpecifier: KeychainItemSpecifier) {
        super.init(securityClass: itemSpecifier.securityClass)
        self.attributes = itemSpecifier.attributes
    }

    public init(securityClass: SecurityClass, itemLabel: String? = nil) {
        super.init(securityClass: securityClass)
        if (itemLabel != nil) {
            attributes[String(kSecAttrLabel)] = itemLabel
        }
    }

    public func keychainQuery() -> [ String: AnyObject ] {
        var dictionary : [ String : AnyObject] = [ : ]
        dictionary[String(kSecClass)] = SecurityClass.kSecClass(securityClass)
        for (attribute, value) in attributes {
            dictionary[attribute] = value
        }
        return dictionary
    }
}


public class KeySpecifier : KeychainItemSpecifier, KeychainQuery {
    public init(keySpecifier: KeySpecifier) {
        super.init(itemSpecifier: keySpecifier)
    }

    public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil,
        keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .Key, itemLabel: keyLabel)
            if keyType != nil {
                attributes[String(kSecAttrKeyType)]          = KeyType.kSecAttrKeyType(keyType!)
            }
            if keySize != nil  {
                attributes[String(kSecAttrKeySizeInBits)]    = keySize!
            }
            if keyClass != nil {
                attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(keyClass!)
            }
            if keyAppLabel != nil {
                attributes[String(kSecAttrApplicationLabel)] = KeySpecifier.encodeKeyAppLabel(keyAppLabel)
            }
            if keyAppTag != nil {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag!
            }
    }
    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }
}


public protocol KeyPairQuery : KeychainQuery {
    func privateKeySpecifier() -> KeySpecifier
    func publicKeySpecifier() -> KeySpecifier
}



public class KeySpecification : KeySpecifier {
    public class func specification(PEMEncodedPrivateKey privateKeyData: NSData, passphrase: String, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) -> KeyPairImportSpecification? {
        var error: NSError? = nil
        if let openSSLKeyPair = OpenSSL.keyPairFromPEMData(privateKeyData, encryptedWithPassword: passphrase, error:&error) {
            return KeyPairImportSpecification(openSSLKeypair: openSSLKeyPair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        }
        return nil;
    }

    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

}

public class KeyPairSpecification : KeySpecification, KeyPairQuery {
    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func privateKeySpecifier() -> KeySpecifier {
        var specifier = KeySpecifier(keySpecifier: self)
        specifier.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
        return specifier
    }

    public func publicKeySpecifier() -> KeySpecifier {
        var specifier = KeySpecifier(keySpecifier: self)
        specifier.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
        return specifier
    }
}



public class TemporaryKeyPairSpecification : KeyPairSpecification, KeyPairQuery {
    public init(keyType: KeyType, keySize: Int) {
        super.init(keyType: keyType, keySize: keySize)
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: false)
    }
}


public class PermanentKeyPairSpecification : KeyPairSpecification, KeyPairQuery {
    public init(keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: true)
    }
}

public class KeyPairImportSpecification : KeyPairSpecification {
    let openSSLKeyPair: OpenSSLKeyPair
    public init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        self.openSSLKeyPair = keypair
        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
    }
    public override func privateKeySpecifier() -> KeySpecifier {
        let specifier = super.privateKeySpecifier()
        specifier.attributes[String(kSecValueData)] = openSSLKeyPair.privateKeyData
        return specifier
    }
    public override func publicKeySpecifier() -> KeySpecifier {
        let specifier = super.publicKeySpecifier()
        specifier.attributes[String(kSecValueData)] = openSSLKeyPair.publicKeyData
        return specifier
    }

}
