//
//  DetachedKey.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
//

import Foundation
import ConfidoIOS

func += <KeyType, ValueType> (inout left: Dictionary<KeyType, ValueType>, right: Dictionary<KeyType, ValueType>) {
    for (k, v) in right {
        left.updateValue(v, forKey: k)
    }
}

extension KeychainPrivateKey {
    //This extension makes it possible to extract the private key data. This is insecure, but only used for testing. This will not work on a device.
    public func keyData() throws ->  NSData  {
        // It is possible that a key is not permanent, then there isn't any data to return
        var query : KeyChainPropertiesData = [ : ]

        let descriptor = keychainMatchPropertyValues()
        query[String(kSecClass)]            = kSecClassKey
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne
        query += descriptor.attributes

        let keyData: NSData = try SecurityWrapper.secItemCopyMatching(query)
        return keyData
    }
}

@objc public class OpenSSLKeyPair : OpenSSLObject {
    @objc public private(set) var privateKeyData: NSData
    @objc public private(set) var publicKeyData: NSData
    public private(set) var keyLength: Int
    public private(set) var keyType: KeyType
    public init(keyLength: Int, keyType: KeyType, privateKeyData: NSData, publicKeyData: NSData) {
        self.privateKeyData = privateKeyData
        self.publicKeyData = publicKeyData
        self.keyType = keyType
        self.keyLength = keyLength
        super.init()
    }
    @objc public var publicKeyDataWithX509Header: NSData {
        get {
            return publicKeyData.dataByPrependingX509RSAHeader()
        }
    }
    func publicKeyDataWithX590Header() -> NSData? {
        return nil;
    }
}

@objc public class OpenSSLRSAKeyPair: OpenSSLKeyPair {
    @objc public init(keyLength: Int, privateKeyData: NSData, publicKeyDataWithX509Header: NSData) {
        let publicKeyData = publicKeyDataWithX509Header.dataByStrippingX509RSAHeader()
        super.init(keyLength: keyLength, keyType: .RSA, privateKeyData: privateKeyData, publicKeyData: publicKeyData)
    }
    public init(keyLength: Int, privateKeyData: NSData, publicKeyData: NSData) {
        super.init(keyLength: keyLength, keyType: .RSA, privateKeyData: privateKeyData, publicKeyData: publicKeyData)
    }

    override func publicKeyDataWithX590Header() -> NSData? {
        return publicKeyData.dataByPrependingX509RSAHeader()
    }
}



