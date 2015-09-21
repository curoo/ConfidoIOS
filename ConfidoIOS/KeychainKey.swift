//
//  KeychainKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation


public class KeychainKey : KeychainItem, KeychainKeyClassProperties {
    public class func keychainKeyFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainKey {
        let keyClass = KeyClass.keyClass(attributes[String(kSecAttrKeyClass)])
        switch keyClass {
        case .PrivateKey: return try KeychainPrivateKey(SecItemAttributes: attributes)
        case .PublicKey:  return try KeychainPublicKey(SecItemAttributes: attributes)
        default:          return try KeychainKey(SecItemAttributes: attributes)
        }
    }

    var keySecKey: SecKey?

    public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        keySecKey = keyRef
        super.init(securityClass: .Key,  byCopyingAttributes: descriptor)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Key, SecItemAttributes: attributes)
        self.keySecKey = try KeychainKey.getKeySecKey(SecItemAttributes: attributes)
    }

    class func getKeySecKey(SecItemAttributes attributes: NSDictionary) throws -> SecKey {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecKeyGetTypeID() {
                return (valueRef as! SecKey)
            }
        }
        throw KeychainError.NoSecKeyReference
    }

    override public func specifierMatchingProperties() -> Set<String> {
       return kKeyItemMatchingProperties
    }


    public lazy var keyData: NSData? = {
        // It is possible that a key is not permanent, then there isn't any data to return
        do {
            return try Keychain.keyData(self)
        }
        catch let error {
            //TODO: Fix
            print("error \(error)")
            return nil
        }
        }()
}


