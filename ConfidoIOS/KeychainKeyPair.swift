//
//  PublicPrivateKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 25/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//




import Foundation
import Security


public protocol Key {
}

public protocol PublicKey : Key {
}


extension PublicKey where Self : PublicKey {
}


public protocol PrivateKey : Key {
}

extension PublicKey where Self : PublicKey {
}

/**
An instance of an IOS Keychain Public Key
*/
public class KeychainPublicKey : KeychainKey, PublicKey, KeychainFindable, GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainPublicKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }
}


/**
An instance of an IOS Keychain Private Key
*/
public class KeychainPrivateKey : KeychainKey, PrivateKey, KeychainFindable,  GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainPrivateKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }
}

public protocol KeyPair {
    typealias PrivKeyType : PrivateKey
    typealias PubKeyType  : PublicKey
    typealias KeyPairTransportClass
    typealias GeneratorDescriptorClass
    var privateKey: PrivKeyType! { get }
    var publicKey: PubKeyType!  { get }
    init (publicKey: PubKeyType, privateKey: PrivKeyType)
    static func generateKeyPair(descriptor: GeneratorDescriptorClass) throws -> KeyPairTransportClass
}


extension KeyPair where Self : KeyPair {
}


public func secEnsureOK(status: OSStatus) throws {
    if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
}



/**
An instance of an IOS Keypair
*/

public class KeychainKeyPair : KeychainItem, KeyPair, KeychainFindable {
    public private(set) var privateKey: KeychainPrivateKey!
    public private(set) var publicKey:  KeychainPublicKey!

    public class func generateKeyPair(descriptor: KeychainKeyPairDescriptor) throws -> KeychainKeyPair {
        var publicKeyRef  : SecKey?
        var privateKeyRef : SecKey?

        try secEnsureOK(SecKeyGeneratePair(descriptor.keychainMatchPropertyValues(), &publicKeyRef, &privateKeyRef))

        return try findInKeychain(descriptor)!
        
    }

    public class func importKeyPair(pemEncodedData keyData: NSData, encryptedWithPassphrase passphrase: String, keyLabel: String? = nil , keyAppTag: String? = nil, keyAppLabel: String? = nil) throws -> TransportKeyPair {
        let openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keyData, encryptedWithPassword: passphrase)
        return TransportKeyPair(openSSLKeypair: openSSLKeyPair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public class func findInKeychain(matchingDescriptor: KeychainKeyPairDescriptor) throws -> KeychainKeyPair? {
        let privateKey = try KeychainPrivateKey.findInKeychain(matchingDescriptor.privateKeyDescriptor()  as KeychainPrivateKey.QueryType)
        let publicKey = try KeychainPublicKey.findInKeychain(matchingDescriptor.publicKeyDescriptor())
        if let privateKey = privateKey, let publicKey = publicKey {
            return KeychainKeyPair(publicKey: publicKey as KeychainPublicKey, privateKey: privateKey as KeychainPrivateKey)
        }
        return nil
    }


    public init(descriptor: KeychainKeyPairDescriptor, publicKeyRef: SecKey, privateKeyRef: SecKey) {
        self.privateKey = KeychainPrivateKey(descriptor: descriptor, keyRef: privateKeyRef)
        self.publicKey  = KeychainPublicKey(descriptor: descriptor, keyRef: publicKeyRef)
        super.init(securityClass: SecurityClass.Key)
    }

    public required init (publicKey: KeychainPublicKey, privateKey: KeychainPrivateKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
        super.init(securityClass: SecurityClass.Key)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Key, SecItemAttributes: attributes)

        self.privateKey = try KeychainPrivateKey(SecItemAttributes: attributes)
        self.publicKey  = try KeychainPublicKey(SecItemAttributes: attributes)
    }

    public func certificateSigningRequest(attributes: [ String : String]) -> NSData? {
        if let openSSLKeyPair = self.openSSLKeyPair {
            do {
                return try OpenSSL.generateCSRWithKeyPair(openSSLKeyPair, csrData: attributes)
            } catch _ {
                return nil
            }
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

//MARK: Transport Key

public class TransportPrivateKey : KeychainKeyDescriptor, SecItemAddable {
    init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String?, keyAppTag: String?, keyAppLabel: String?) {
        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyClass: .PrivateKey, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        attributes[String(kSecValueData)] = keypair.privateKeyData

    }
}

public class TransportPublicKey : KeychainKeyDescriptor, SecItemAddable {
    init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String?, keyAppTag: String?, keyAppLabel: String?) {
        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyClass: .PublicKey, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        attributes[String(kSecValueData)] = keypair.publicKeyData
    }
}


public class TransportKeyPair :KeychainKeyPairDescriptor,  KeychainAddable {
    //Marks that this class maps to KeychainKeyPair when matching
    public typealias KeychainClassType = KeychainKeyPair

    let openSSLKeyPair: OpenSSLKeyPair
    let privateKey : TransportPrivateKey
    let publicKey  : TransportPublicKey
    public init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String? , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        self.openSSLKeyPair = keypair
        self.privateKey = TransportPrivateKey(openSSLKeypair: keypair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        self.publicKey = TransportPublicKey(openSSLKeypair: keypair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)

        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyClass: nil, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func addToKeychain() throws -> KeychainKeyPair? {
        try privateKey.addToKeychain()
        try publicKey.addToKeychain()

        return try KeychainKeyPair.findInKeychain(self)
    }
}

//MARK: Key Pair Descriptors
public class TemporaryKeychainKeyPairDescriptor : KeychainKeyPairDescriptor {
    public init(keyType: KeyType, keySize: Int) {
        super.init(keyType: keyType, keySize: keySize)
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: false)
    }
}

public class PermanentKeychainKeyPairDescriptor : KeychainKeyPairDescriptor {
    /**
    :param:   keyType     Type of key pair to generate (RSA or EC)
    :param:   keySize     Size of the key to generate
    :param:   keyLabel    A searchable label for the key pair
    :param:   keyAppTag
    :returns: keyAppLabel The kSecAttrAppLabel to add to the keychain item. By default this is the hash of the public key and should be set to nit
    */
    public init(accessible: Accessible, accessControl: SecAccessControl?, keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: true)
        attributes[String(kSecAttrAccessible)] = accessible.rawValue
        if (accessControl != nil) {
            attributes[String(kSecAttrAccessControl)] = accessControl
        }
    }
}



