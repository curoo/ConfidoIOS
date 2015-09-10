//
//  PublicPrivateKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 25/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//




import Foundation
import Security



public class PublicKey : KeychainKey {
    override public init(specification: KeySpecification, keyRef: SecKey) {
        super.init(specification: specification, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

    public override init(keychainAttributes attributes: NSDictionary) {
        super.init(keychainAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

}

public class PrivateKey : KeychainKey {
    override public init(specification: KeySpecification, keyRef: SecKey) {
        super.init(specification: specification, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }

    public override init(keychainAttributes attributes: NSDictionary) {
        super.init(keychainAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }
}

public class KeyPair : KeychainItem {
    public let privateKey: PrivateKey
    public let publicKey: PublicKey

    public init(specification: KeyPairSpecification, publicKeyRef: SecKey, privateKeyRef: SecKey) {
        self.privateKey = PrivateKey(specification: specification, keyRef: privateKeyRef)
        self.publicKey  = PublicKey(specification: specification, keyRef: publicKeyRef)
        super.init(securityClass: .Key)
    }

    public init (publicKey: PublicKey, privateKey: PrivateKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
        super.init(securityClass: .Key)
    }

    public init(keychainAttributes attributes: NSDictionary) {
        self.privateKey = PrivateKey(keychainAttributes: attributes)
        self.publicKey  = PublicKey(keychainAttributes: attributes)
        super.init(securityClass: .Key, keychainAttributes: attributes)
    }

    public func certificateSigningRequest(attributes: [ String : String]) -> NSData? {
        if let openSSLKeyPair = self.openSSLKeyPair,
            let privateKeyData = self.privateKey.keyData,
            let publicKeyData = self.publicKey.keyData {
            var error: NSError?
            return OpenSSL.generateCSRWithKeyPair(openSSLKeyPair, csrData: attributes, error: &error)
        }
        return nil
    }

    public lazy var openSSLKeyPair : OpenSSLKeyPair? = {
        if self.privateKey.keyType == .RSA,
            let privateKeyData = self.privateKey.keyData, let publicKeyData = self.publicKey.keyData {
            return OpenSSLRSAKeyPair(keyLength: self.publicKey.keySize, privateKeyData: privateKeyData, publicKeyData: publicKeyData)
        }
        return nil;
    }()
}



