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
            attributes[.Label] = itemLabel
        }
    }

    public func keychainQuery() -> [ String: AnyObject ] {
        var dictionary : [ String : AnyObject] = [ : ]
        dictionary[String(kSecClass)] = SecurityClass.kSecClass(securityClass)
        for (attribute, value) in attributes {
            let key = SecAttr.kSecAttr(attribute)
            dictionary[String(key)] = value
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
                attributes[.KeyType]          = KeyType.kSecAttrKeyType(keyType!)
            }
            if keySize != nil  {
                attributes[.KeySizeInBits]    = keySize!
            }
            if keyClass != nil {
                attributes[.KeyClass]         = KeyClass.kSecAttrKeyClass(keyClass!)
            }
            if keyAppLabel != nil {
                attributes[.ApplicationLabel] = KeySpecifier.encodeKeyAppLabel(keyAppLabel)
            }
            if keyAppTag != nil {
                attributes[.ApplicationTag]   = keyAppTag!
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
        specifier.attributes[.KeyClass] = KeyClass.kSecAttrKeyClass(.PrivateKey)
        return specifier
    }

    public func publicKeySpecifier() -> KeySpecifier {
        var specifier = KeySpecifier(keySpecifier: self)
        specifier.attributes[.KeyClass] = KeyClass.kSecAttrKeyClass(.PublicKey)
        return specifier
    }
}



public class TemporaryKeyPairSpecification : KeyPairSpecification, KeyPairQuery {
    public init(keyType: KeyType, keySize: Int) {
        super.init(keyType: keyType, keySize: keySize)
        attributes[.IsPermanent] = NSNumber(bool: false)
    }
}


public class PermanentKeyPairSpecification : KeyPairSpecification, KeyPairQuery {
    public init(keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
        attributes[.IsPermanent] = NSNumber(bool: true)
    }
}

