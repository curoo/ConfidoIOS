//
//  Itemdescriptor.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//

import Foundation


/*
Base class for queries to the keychain. Used to derive things like specifications for generating keys, searching the IOS Keychain, etc.
*/


public class KeychainKeyDescriptor : KeychainDescriptor {
    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }


    public init(keyDescriptor: KeychainKeyDescriptor) {
        super.init(descriptor: keyDescriptor)
    }

    public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil,
        keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .Key, itemLabel: keyLabel)
            if keyType != nil {
                attributes[String(kSecAttrKeyType)]          = keyType!.rawValue
            }
            if keySize != nil  {
                attributes[String(kSecAttrKeySizeInBits)]    = keySize!
            }
            if keyClass != nil {
                attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(keyClass!)
            }
            if keyAppLabel != nil {
                attributes[String(kSecAttrApplicationLabel)] = KeychainKeyDescriptor.encodeKeyAppLabel(keyAppLabel)
            }
            if keyAppTag != nil {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag!
            }
    }
}

public protocol KeyPairQueryable {
    func privateKeyDescriptor() -> KeychainKeyDescriptor
    func publicKeyDescriptor() -> KeychainKeyDescriptor
}

public class KeychainKeyPairDescriptor : KeychainKeyDescriptor, KeyPairQueryable {
    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func privateKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor(keyDescriptor: self)
        descriptor.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
        return descriptor
    }

    public func publicKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor(keyDescriptor: self)
        descriptor.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
        return descriptor
    }
}





