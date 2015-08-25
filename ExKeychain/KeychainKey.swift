//
//  KeychainKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

public class KeychainKey : KeychainItem {

    public class func keychainKeyFromAttributes(keychainAttributes attributes: NSDictionary) -> KeychainKey? {
        let keyClass = KeyClass.keyClass(attributes[String(kSecAttrKeyClass)])
        switch keyClass {
        case .PrivateKey: return PrivateKey(keychainAttributes: attributes)
        case .PublicKey:  return PublicKey(keychainAttributes: attributes)
        default:          return KeychainKey(keychainAttributes: attributes)
        }
    }

    var keySecKey: SecKey?

    public init(specification: KeySpecification, keyRef: SecKey) {
        keySecKey = keyRef
        super.init(securityClass: .Key,  attributeBag: specification)
    }

    public init(keychainAttributes attributes: NSDictionary) {
        super.init(securityClass: .Key, keychainAttributes: attributes)
        self.keySecKey = KeychainKey.getKeySecKey(keychainAttributes: attributes)
    }

    class func getKeySecKey(keychainAttributes attributes: NSDictionary) -> SecKey? {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecKeyGetTypeID() {
                return (valueRef as! SecKey)
            }
        }
        return nil
    }

    override public func specifierMatchingProperties() -> Set<SecAttr> {
       return kKeyItemMatchingProperties
    }

    public var keyAppTag: String? {
        get { return attributes[.ApplicationTag] as? String }
    }

    public var keyAppLabel: String? {
        get {
            if let data = attributes[.ApplicationLabel] as? NSData {
                return NSString(data: data, encoding: NSUTF8StringEncoding) as? String
            } else {
                return nil
            }
        }
    }

    public var keyClass: KeyClass {
        get {
            return KeyClass.keyClass(attributes[.KeyClass])
        }
    }

    public var keyType:  KeyType {
        get { return KeyType.keyType(attributes[.KeyType]!) }
    }

    public var keySize: Int {
        get {
            return (attributes[.KeySizeInBits] as? NSNumber)!.integerValue
        }
    }

    public var keyPermanent: Bool {
        get {
            return (attributes[.IsPermanent] as? NSNumber)?.boolValue ?? false
        }
    }

    public lazy var keyData: NSData? = {
        // It is possible that a key is not permanent, then there isn't any data to return
        let (result, optionalData) = Keychain.keyData(self)
        return optionalData
        }()
}


