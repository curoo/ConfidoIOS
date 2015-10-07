//
//  PublicPrivateKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 25/08/2015.
//
//




import Foundation
import Security

public typealias Signature = Buffer<Byte>
public typealias Digest    = Buffer<Byte>


public protocol Key {
}

public protocol PublicKey : Key {
    func verify(digest: Digest, signature: Signature) throws ->  Bool
    func encrypt(plaintext: Buffer<Byte>, padding: SecPadding) throws -> Buffer<Byte>
}


extension Key where Self : Key, Self : KeychainKey {

}
extension PublicKey where Self : PublicKey, Self: KeychainKey {
    public func encrypt(plainText: Buffer<Byte>, padding: SecPadding) throws -> Buffer<Byte> {
        try ensureRSAOrECKey()
        let maxBlockSize = SecKeyGetBlockSize(self.keySecKey!)
        if plainText.size > maxBlockSize {
            throw KeychainError.DataExceedsBlockSize(size: maxBlockSize)
        }
        var cipherText = Buffer<Byte>(size: maxBlockSize)
        var returnSize = maxBlockSize

        try ensureOK(SecKeyEncrypt(self.keySecKey!, padding, plainText.values, plainText.size, cipherText.mutablePointer, &returnSize))
        cipherText.size = returnSize
        return cipherText
    }

    public func verify(digest: Digest, signature: Signature) throws -> Bool {
        try ensureRSAOrECKey()
        let status = SecKeyRawVerify(self.keySecKey!, SecPadding.PKCS1, digest.values, digest.size, signature.values, signature.size)
        if status == 0 { return true }
        return false
    }
}

public protocol PrivateKey : Key {
    func sign(digest: Digest) throws -> Signature
    func decrypt(cipherBlock: Buffer<Byte>, padding: SecPadding) throws -> Buffer<Byte>
}

extension KeychainPrivateKey {
    public func decrypt(cipherText: Buffer<Byte>, padding: SecPadding) throws -> Buffer<Byte> {
        try ensureRSAOrECKey()
        let maxBlockSize = SecKeyGetBlockSize(self.keySecKey!)
        if cipherText.size > maxBlockSize {
            throw KeychainError.DataExceedsBlockSize(size: maxBlockSize)
        }
        var plainText = Buffer<Byte>(size: maxBlockSize)
        var returnSize = maxBlockSize

        try ensureOK(SecKeyDecrypt(self.keySecKey!, padding, cipherText.values, cipherText.size, plainText.mutablePointer, &returnSize))
        plainText.size = returnSize
        return plainText
    }

    public func sign(digest: Digest) throws -> Signature {
        try ensureRSAOrECKey()

        var signatureLength : Int = self.keyType!.signatureMaxSize(self.keySize)
        var signature = Buffer<Byte>(size: signatureLength)
        try ensureOK(SecKeyRawSign(self.keySecKey!, SecPadding.PKCS1, digest.values,digest.size, signature.mutablePointer, &signatureLength))
        signature.size = signatureLength
        return signature
    }
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


/**
An instance of an IOS Keychain Private Key
*/


func ensureOK(status: OSStatus) throws {
    if status != 0 {
        throw KeychainStatus.statusFromOSStatus(status)
    }
}


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

    public required init(publicKey: KeychainPublicKey, privateKey: KeychainPrivateKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
        super.init(securityClass: SecurityClass.Key)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Key, SecItemAttributes: attributes)

        self.privateKey = try KeychainPrivateKey(SecItemAttributes: attributes)
        self.publicKey  = try KeychainPublicKey(SecItemAttributes: attributes)
    }
}


//MARK: Key Pair Descriptors

public protocol KeyPairQueryable {
    func privateKeyDescriptor() -> KeychainKeyDescriptor
    func publicKeyDescriptor() -> KeychainKeyDescriptor
}

public class KeychainKeyPairDescriptor : KeychainKeyDescriptor, KeyPairQueryable {
    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func privateKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor()
        descriptor.attributes[String(kSecAttrKeyClass)]       = KeyClass.kSecAttrKeyClass(.PrivateKey)
        descriptor.attributes[String(kSecAttrKeyType)]        = self.attributes[String(kSecAttrKeyType)]
        descriptor.attributes[String(kSecAttrKeySizeInBits)]  = self.attributes[String(kSecAttrKeySizeInBits)]
        descriptor.attributes[String(kSecAttrLabel)]          = self.attributes[String(kSecAttrLabel)]
        if let privAttrs = self.attributes[String(kSecPrivateKeyAttrs)] as? [String:AnyObject] {
            if let privKeyLabel = privAttrs[String(kSecAttrLabel)] as? String {
                descriptor.attributes[String(kSecAttrLabel)]  = privKeyLabel
            }
            if let privKeyAppTag = privAttrs[String(kSecAttrApplicationTag)]  {
                descriptor.attributes[String(kSecAttrApplicationTag)]  = privKeyAppTag
            }

        }
        return descriptor
    }

    public func publicKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor()
        descriptor.attributes[String(kSecAttrKeyClass)]       = KeyClass.kSecAttrKeyClass(.PublicKey)
        descriptor.attributes[String(kSecAttrKeyType)]        = self.attributes[String(kSecAttrKeyType)]
        descriptor.attributes[String(kSecAttrKeySizeInBits)]  = self.attributes[String(kSecAttrKeySizeInBits)]
        descriptor.attributes[String(kSecAttrLabel)]          = self.attributes[String(kSecAttrLabel)]
        if let pubAttrs = self.attributes[String(kSecPublicKeyAttrs)] as? [String:AnyObject] {
            if let pubKeyLabel = pubAttrs[String(kSecAttrLabel)] as? String {
                descriptor.attributes[String(kSecAttrLabel)]  = pubKeyLabel
            }
            if let pubKeyAppTag = pubAttrs[String(kSecAttrApplicationTag)]  {
                descriptor.attributes[String(kSecAttrApplicationTag)]  = pubKeyAppTag
            }

        }
        return descriptor
    }
}


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
    public init(accessible: Accessible, privateKeyAccessControl: SecAccessControl?,publicKeyAccessControl: SecAccessControl?, keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: true)
        attributes[String(kSecAttrAccessible)] = accessible.rawValue
        if (privateKeyAccessControl != nil) {
            attributes[String(kSecPrivateKeyAttrs)] = [ String(kSecAttrAccessControl): privateKeyAccessControl! ]
        }
        if (publicKeyAccessControl != nil) {
            attributes[String(kSecPublicKeyAttrs)] = [ String(kSecAttrAccessControl): publicKeyAccessControl! ]
        }
    }
    public init(accessible: Accessible,
        privateKeyLabel: String, privateKeyAppTag: String?, privateKeyAccessControl: SecAccessControl?,
        publicKeyLabel: String,  publicKeyAppTag: String?,  publicKeyAccessControl: SecAccessControl?,
        keyType: KeyType, keySize: Int) {
            super.init(keyType: keyType, keySize: keySize, keyLabel: nil, keyAppTag: nil, keyAppLabel: nil )
            attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: true)
            attributes[String(kSecAttrAccessible)] = accessible.rawValue

            var privateAttrs  : [String: AnyObject] = [ : ]
            var publicAttrs   : [String: AnyObject] = [ : ]

            attributes[String(kSecPublicKeyAttrs)]  = [ : ]
            if (privateKeyAccessControl != nil) {
                privateAttrs[ String(kSecAttrAccessControl)] = privateKeyAccessControl!
            }
            if (publicKeyAccessControl != nil) {
                publicAttrs[ String(kSecAttrAccessControl)] = publicKeyAccessControl!
            }
            privateAttrs[ String(kSecAttrLabel)] = privateKeyLabel
            publicAttrs[ String(kSecAttrLabel)] = publicKeyLabel

            if (privateKeyAppTag != nil) {
                privateAttrs[ String(kSecAttrApplicationTag)] = privateKeyAppTag!
            }
            if (publicKeyAppTag != nil) {
                publicAttrs[ String(kSecAttrApplicationTag)] = publicKeyAppTag!
            }

            attributes[String(kSecPrivateKeyAttrs)] = privateAttrs
            attributes[String(kSecPublicKeyAttrs)]  = publicAttrs
    }
}



