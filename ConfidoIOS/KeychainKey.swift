//
//  KeychainKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//
//

import Foundation
import CommonCrypto


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

    func ensureRSAOrECKey() throws {
        if (self.keyType == KeyType.RSA) { return }
        if (self.keyType == KeyType.ElypticCurve) { return }

        throw KeychainError.UnimplementedKeyType(reason: "Not implemented for key types other than RSA or EC")
    }
}

/**
An instance of an IOS Keychain Public Key
*/
public class KeychainSymmetricKey : KeychainKey, KeychainFindable, GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainSymmetricKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.SymmetricKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.SymmetricKey)
    }
    public func withKeyDataDo(closure : (NSData)-> Void ) throws {
        // this key's keyData is cryptographic key material and should not be passed around or stored.
        // Use this very carefully
        let keyData = try fetchKeyData(self)
        closure(keyData)
    }
}

func fetchKeyData(key: KeychainKey) throws -> NSData {
    var query : KeyChainPropertiesData = [ : ]

    let descriptor = key.keychainMatchPropertyValues()
    query[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)
    query[String(kSecReturnData)]       = kCFBooleanTrue
    query[String(kSecMatchLimit)]       = kSecMatchLimitOne
    query += descriptor.keychainMatchPropertyValues()

    let keyData: NSData = try SecurityWrapper.secItemCopyMatching(query)
    return keyData

}


extension KeychainSymmetricKey {
}
