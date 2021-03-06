//
//  PublicPrivateKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 25/08/2015.
//
//




import Foundation
import Security

public typealias Signature = ByteBuffer
public typealias Digest    = ByteBuffer


public protocol Key {
}

public protocol PublicKey : Key {
    func verify(_ digest: Digest, signature: Signature) throws ->  Bool
    func encrypt(_ plaintext: ByteBuffer, padding: SecPadding) throws -> ByteBuffer
}


extension Key where Self : Key, Self : KeychainKey {

}
extension PublicKey where Self : PublicKey, Self: KeychainKey {
    public func encrypt(_ plainText: ByteBuffer, padding: SecPadding) throws -> ByteBuffer {
        try ensureRSAOrECKey()
        let maxBlockSize = SecKeyGetBlockSize(self.keySecKey!)
        if plainText.size > maxBlockSize {
            throw KeychainError.dataExceedsBlockSize(size: maxBlockSize)
        }
        var cipherText = ByteBuffer(size: maxBlockSize)
        var returnSize = maxBlockSize

        try ensureOK(SecKeyEncrypt(self.keySecKey!, padding, plainText.values, plainText.size, cipherText.mutablePointer, &returnSize))
        cipherText.size = returnSize
        return cipherText
    }

    public func verify(_ digest: Digest, signature: Signature) throws -> Bool {
        try ensureRSAOrECKey()
        let status = SecKeyRawVerify(self.keySecKey!, SecPadding.PKCS1, digest.values, digest.size, signature.values, signature.size)
        if status == 0 { return true }
        return false
    }
}

public protocol PrivateKey : Key {
    func sign(_ digest: Digest) throws -> Signature
    func decrypt(_ cipherBlock: ByteBuffer, padding: SecPadding) throws -> ByteBuffer
}

extension KeychainPrivateKey {
    public func decrypt(_ cipherText: ByteBuffer, padding: SecPadding) throws -> ByteBuffer {
        try ensureRSAOrECKey()
        let maxBlockSize = SecKeyGetBlockSize(self.keySecKey!)
        if cipherText.size > maxBlockSize {
            throw KeychainError.dataExceedsBlockSize(size: maxBlockSize)
        }
        var plainText = ByteBuffer(size: maxBlockSize)
        var returnSize = maxBlockSize

        try ensureOK(SecKeyDecrypt(self.keySecKey!, padding, cipherText.values, cipherText.size, plainText.mutablePointer, &returnSize))
        plainText.size = returnSize
        return plainText
    }

    public func sign(_ digest: Digest) throws -> Signature {
        try ensureRSAOrECKey()

        var signatureLength : Int = self.keyType!.signatureMaxSize(self.keySize)
        var signature = ByteBuffer(size: signatureLength)
        try ensureOK(SecKeyRawSign(self.keySecKey!, SecPadding.PKCS1, digest.values,digest.size, signature.mutablePointer, &signatureLength))
        signature.size = signatureLength
        return signature
    }
}

/**
An instance of an IOS Keychain Public Key
*/
open class KeychainPublicKey : KeychainKey, PublicKey, KeychainFindable, GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainPublicKey

    open class func importRSAPublicKey(derEncodedData data: Data, keyLabel: String, keyAppTag: String? = nil) throws -> KeychainPublicKey {
        let dataStrippedOfX509Header = data.dataByStrippingX509Header()
        let descriptor = PublicKeyDescriptor(derEncodedKeyData: dataStrippedOfX509Header, keyLabel: keyLabel, keyAppTag: keyAppTag)
        try descriptor.addToKeychain()
        return try KeychainPublicKey.findInKeychain(descriptor)!
    }

    open class func existingKeys(_ matchingDescriptor: PublicKeyMatchingDescriptor) -> [KeychainKey] {
       return try! Keychain.fetchItems(matchingDescriptor: matchingDescriptor, returning: .all) as! [KeychainKey]
    }

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.publicKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.publicKey)
    }
    open lazy var keyData: Data? = {
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


public func ensureOK(_ status: OSStatus) throws {
    if status != 0 {
        throw KeychainStatus.statusFromOSStatus(status)
    }
}


open class KeychainPrivateKey : KeychainKey, PrivateKey, KeychainFindable,  GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainPrivateKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.privateKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.privateKey)
    }
}

public protocol KeyPair {
    associatedtype PrivKeyType : PrivateKey
    associatedtype PubKeyType  : PublicKey
    associatedtype KeyPairTransportClass
    associatedtype GeneratorDescriptorClass
    var privateKey: PrivKeyType! { get }
    var publicKey: PubKeyType!  { get }
    init (publicKey: PubKeyType, privateKey: PrivKeyType)
    static func generateKeyPair(_ descriptor: GeneratorDescriptorClass) throws -> KeyPairTransportClass
}


extension KeyPair where Self : KeyPair {
}

public func secEnsureOK(_ status: OSStatus) throws {
    if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
}

/**
An instance of an IOS Keypair
*/

open class KeychainKeyPair : KeychainItem, KeyPair, KeychainFindable {
    open fileprivate(set) var privateKey: KeychainPrivateKey!
    open fileprivate(set) var publicKey:  KeychainPublicKey!

    open class func generateKeyPair(_ descriptor: KeychainKeyPairDescriptor) throws -> KeychainKeyPair {
        var publicKeyRef  : SecKey?
        var privateKeyRef : SecKey?

        try secEnsureOK(SecKeyGeneratePair(descriptor.keychainMatchPropertyValues() as CFDictionary, &publicKeyRef, &privateKeyRef))

        return try findInKeychain(descriptor)!
    }

    open class func findInKeychain(_ matchingDescriptor: KeychainKeyPairDescriptor) throws -> KeychainKeyPair? {
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
        super.init(securityClass: SecurityClass.key)
    }

    public required init(publicKey: KeychainPublicKey, privateKey: KeychainPrivateKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
        super.init(securityClass: SecurityClass.key)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.key, SecItemAttributes: attributes)

        self.privateKey = try KeychainPrivateKey(SecItemAttributes: attributes)
        self.publicKey  = try KeychainPublicKey(SecItemAttributes: attributes)
    }
}


//MARK: Key Pair Descriptors

public protocol KeyPairQueryable {
    func privateKeyDescriptor() -> KeychainKeyDescriptor
    func publicKeyDescriptor() -> KeychainKeyDescriptor
}

open class PublicKeyDescriptor: KeychainKeyDescriptor, SecItemAddable {
    public init(derEncodedKeyData data: Data, keyLabel: String?, keyAppTag: String?) {
        let size = PublicKeyDescriptor.guessBitSize(data)
        super.init(keyType: KeyType.rsa, keySize: size, keyClass: KeyClass.publicKey, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: nil)
        attributes[String(kSecValueData)] = data as AnyObject?
    }

    @discardableResult open func addToKeychain() throws -> KeychainPublicKey {
        try self.secItemAdd()
        //This is a hack because you cannot query on kSecValueData. At this time the query dictionary contains the
        //binary representation of they key, we need to remove it from the dictionary for the next call or it won't work.
        attributes.removeValue(forKey: String(kSecValueData))
        return try KeychainPublicKey.findInKeychain(self)!
    }


    class func guessBitSize(_ data: Data) -> Int {
        let len = data.count
        switch (len/64) {
        case 1: return 512
        case 2: return 1024
        case 4: return 2048
        case 8: return 4096
        default:
            fatalError("Could not estimate size of RSA key with input data length \(len)")
        }
    }
}

open class PublicKeyMatchingDescriptor: KeychainKeyDescriptor {
    public init(keyLabel: String?, keyAppTag: String?) {
        super.init(keyType: KeyType.rsa, keySize: nil, keyClass: KeyClass.publicKey, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: nil)
    }
}

open class KeychainKeyPairDescriptor : KeychainKeyDescriptor, KeyPairQueryable {
    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    open func privateKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor()
        descriptor.attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(.privateKey)
        descriptor.attributes[String(kSecAttrKeyType)]          = self.attributes[String(kSecAttrKeyType)]
        descriptor.attributes[String(kSecAttrKeySizeInBits)]    = self.attributes[String(kSecAttrKeySizeInBits)]
        descriptor.attributes[String(kSecAttrLabel)]            = self.attributes[String(kSecAttrLabel)]
        descriptor.attributes[String(kSecAttrApplicationLabel)] = self.attributes[String(kSecAttrApplicationLabel)]

        if let privAttrs = self.attributes[String(kSecPrivateKeyAttrs)] as? [String:AnyObject] {
            if let privKeyLabel = privAttrs[String(kSecAttrLabel)] as? String {
                descriptor.attributes[String(kSecAttrLabel)]  = privKeyLabel as AnyObject?
            }
            if let privKeyAppTag = privAttrs[String(kSecAttrApplicationTag)]  {
                descriptor.attributes[String(kSecAttrApplicationTag)]  = privKeyAppTag
            }

            if let privKeyAppLabel = privAttrs[String(kSecAttrApplicationLabel)]  {
                descriptor.attributes[String(kSecAttrApplicationLabel)] = privKeyAppLabel
            }
        }
        return descriptor
    }

    open func publicKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor()
        descriptor.attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(.publicKey)
        descriptor.attributes[String(kSecAttrKeyType)]          = self.attributes[String(kSecAttrKeyType)]
        descriptor.attributes[String(kSecAttrKeySizeInBits)]    = self.attributes[String(kSecAttrKeySizeInBits)]
        descriptor.attributes[String(kSecAttrLabel)]            = self.attributes[String(kSecAttrLabel)]
        descriptor.attributes[String(kSecAttrApplicationLabel)] = self.attributes[String(kSecAttrApplicationLabel)]

        if let pubAttrs = self.attributes[String(kSecPublicKeyAttrs)] as? [String:AnyObject] {
            if let pubKeyLabel = pubAttrs[String(kSecAttrLabel)] as? String {
                descriptor.attributes[String(kSecAttrLabel)]  = pubKeyLabel as AnyObject?
            }
            if let pubKeyAppTag = pubAttrs[String(kSecAttrApplicationTag)]  {
                descriptor.attributes[String(kSecAttrApplicationTag)]  = pubKeyAppTag
            }
            if let pubKeyAppLabel = pubAttrs[String(kSecAttrApplicationLabel)]  {
                descriptor.attributes[String(kSecAttrApplicationLabel)] = pubKeyAppLabel
            }

        }
        return descriptor
    }
}


open class TemporaryKeychainKeyPairDescriptor : KeychainKeyPairDescriptor {
    public init(keyType: KeyType, keySize: Int) {
        super.init(keyType: keyType, keySize: keySize)
        attributes[String(kSecAttrIsPermanent)] = NSNumber(value: false as Bool)
    }
}

open class PermanentKeychainKeyPairDescriptor : KeychainKeyPairDescriptor {
    /**
    :param:   keyType     Type of key pair to generate (RSA or EC)
    :param:   keySize     Size of the key to generate
    :param:   keyLabel    A searchable label for the key pair
    :param:   keyAppTag
    :param: publicKeyAppLabel The kSecAttrAppLabel to add to the keychain item. By default this is the hash of the public key and should be set to nil
    */
    public init(accessible: Accessible, privateKeyAccessControl: SecAccessControl?,publicKeyAccessControl: SecAccessControl?, keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, publicKeyAppLabel: String = "public") {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: nil )
        attributes[String(kSecAttrAccessible)] = accessible.rawValue as AnyObject?

        var privateAttrs  : [String: AnyObject] = [ : ]
        var publicAttrs   : [String: AnyObject] = [ : ]

        privateAttrs[ String(kSecAttrIsPermanent)]     =  NSNumber(value: true as Bool)
        publicAttrs [String(kSecAttrIsPermanent)]      = NSNumber(value: true as Bool)
        /** We assign a label to the public key, to avoid a bug in the keychain where both private and 
            public keys are marked "private" and when combined with certificate, results in two identities (only one valid) to be returned
            The mechanism uses a query " WHERE keys.priv == 1 AND cert.pkhh == keys.klbl" to find matching keys. By overiding the 
            public key's KeyAppLabel, it won't match, and only the correct identity is returned
        
        @constant kSecAttrApplicationLabel Specifies a dictionary key whose value
        is the key's application label attribute. This is different from the
        kSecAttrLabel (which is intended to be human-readable). This attribute
        is used to look up a key programmatically; in particular, for keys of
        class kSecAttrKeyClassPublic and kSecAttrKeyClassPrivate, the value of
        this attribute is the hash of the public key.
        */
        publicAttrs [String(kSecAttrApplicationLabel)] = publicKeyAppLabel as AnyObject?

        if let privateKeyAccessControl = privateKeyAccessControl {
            privateAttrs[ String(kSecAttrAccessControl)] =  privateKeyAccessControl
        }
        if let publicKeyAccessControl = publicKeyAccessControl {
            publicAttrs[ String(kSecAttrAccessControl)] =  publicKeyAccessControl
        }

        attributes[String(kSecPrivateKeyAttrs)] = privateAttrs as AnyObject?
        attributes[String(kSecPublicKeyAttrs)]  = publicAttrs as AnyObject?

    }
    public init(accessible: Accessible, keyLabel: String,
        privateKeyAppTag: String?, privateKeyAccessControl: SecAccessControl?,
        publicKeyAppLabel: String = "public",  publicKeyAppTag: String?,  publicKeyAccessControl: SecAccessControl?,
        keyType: KeyType, keySize: Int) {
            super.init(keyType: keyType, keySize: keySize, keyLabel: keyLabel, keyAppTag: nil, keyAppLabel: nil )
            attributes[String(kSecAttrAccessible)] = accessible.rawValue as AnyObject?

            var privateAttrs  : [String: AnyObject] = [ : ]
            var publicAttrs   : [String: AnyObject] = [ : ]
            privateAttrs[String(kSecAttrIsPermanent)] = NSNumber(value: true as Bool)
            publicAttrs [String(kSecAttrIsPermanent)] = NSNumber(value: true as Bool)

            /** We assign a label to the public key, to avoid a bug in the keychain where both private and
            public keys are marked "private" and when combined with certificate, results in two identities (only one valid) to be returned
            The mechanism uses a query " WHERE keys.priv == 1 AND cert.pkhh == keys.klbl" to find matching keys. By overiding the
            public key's KeyAppLabel, it won't match, and only the correct identity is returned
            */
            publicAttrs [String(kSecAttrApplicationLabel)] = publicKeyAppLabel as AnyObject?

            if let privateKeyAccessControl = privateKeyAccessControl {
                privateAttrs[ String(kSecAttrAccessControl)] = privateKeyAccessControl
            }
            if let publicKeyAccessControl = publicKeyAccessControl {
                publicAttrs[ String(kSecAttrAccessControl)] = publicKeyAccessControl
            }

            if let privateKeyAppTag = privateKeyAppTag {
                privateAttrs[ String(kSecAttrApplicationTag)] = privateKeyAppTag as AnyObject?
            }
            if let publicKeyAppTag = publicKeyAppTag {
                publicAttrs[ String(kSecAttrApplicationTag)] = publicKeyAppTag as AnyObject?
            }

            attributes[String(kSecPrivateKeyAttrs)] = privateAttrs as AnyObject?
            attributes[String(kSecPublicKeyAttrs)]  = publicAttrs as AnyObject?
    }
}


//https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift


extension NSInteger {
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)];
        }

        // Long form
        let i = (self / 256) + 1
        var len = self
        var result: [CUnsignedChar] = [CUnsignedChar(i + 0x80)]

        for _ in 0 ..< i {
            result.insert(CUnsignedChar(len & 0xFF), at: 1)
            len = len >> 8
        }

        return result
    }

    init?(octetBytes: [CUnsignedChar], startIdx: inout NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] as UInt8 - 128)

            if octets > octetBytes.count - startIdx {
                self.init(0)
                return nil
            }

            var result = UInt64(0)

            for j in 1...octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIdx + j])
            }

            startIdx += 1 + octets
            self.init(result)
        }
    }
}


extension Data {
    init(modulus: Data, exponent: Data) {
        // Make sure neither the modulus nor the exponent start with a null byte
        var modulusBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: (modulus as NSData).bytes.bindMemory(to: CUnsignedChar.self, capacity: modulus.count), count: modulus.count / MemoryLayout<CUnsignedChar>.size))
        let exponentBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: (exponent as NSData).bytes.bindMemory(to: CUnsignedChar.self, capacity: exponent.count), count: exponent.count / MemoryLayout<CUnsignedChar>.size))

        // Make sure modulus starts with a 0x00
        if let prefix = modulusBytes.first , prefix != 0x00 {
            modulusBytes.insert(0x00, at: 0)
        }

        // Lengths
        let modulusLengthOctets = modulusBytes.count.encodedOctets()
        let exponentLengthOctets = exponentBytes.count.encodedOctets()

        // Total length is the sum of components + types
        let totalLengthOctets = (modulusLengthOctets.count + modulusBytes.count + exponentLengthOctets.count + exponentBytes.count + 2).encodedOctets()

        // Combine the two sets of data into a single container
        var builder: [CUnsignedChar] = []
        let data = NSMutableData()

        // Container type and size
        builder.append(0x30)
        builder.append(contentsOf: totalLengthOctets)
        data.append(builder, length: builder.count)
        builder.removeAll(keepingCapacity: false)

        // Modulus
        builder.append(0x02)
        builder.append(contentsOf: modulusLengthOctets)
        data.append(builder, length: builder.count)
        builder.removeAll(keepingCapacity: false)
        data.append(modulusBytes, length: modulusBytes.count)

        // Exponent
        builder.append(0x02)
        builder.append(contentsOf: exponentLengthOctets)
        data.append(builder, length: builder.count)
        data.append(exponentBytes, length: exponentBytes.count)

        self.init(bytes: data.bytes, count: data.length)
    }

    func splitIntoComponents() -> (modulus: Data, exponent: Data)? {
        // Get the bytes from the keyData
        let pointer = (self as NSData).bytes.bindMemory(to: CUnsignedChar.self, capacity: self.count)
        let keyBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start:pointer, count:self.count / MemoryLayout<CUnsignedChar>.size))

        // Assumption is that the data is in DER encoding
        // If we can parse it, then return successfully
        var i: NSInteger = 0

        // First there should be an ASN.1 SEQUENCE
        if keyBytes[0] != 0x30 {
            return nil
        } else {
            i += 1
        }
        // Total length of the container
        if let _ = NSInteger(octetBytes: keyBytes, startIdx: &i) {
            // First component is the modulus
            if keyBytes[i] == 0x02 {
                i += 1
                if let modulusLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                    let modulus = self.subdata(in: NSRange(location: i, length: modulusLength).toRange()!)
                    i += modulusLength

                    // Second should be the exponent
                    if keyBytes[i] == 0x02 {
                        i += 1
                        if let exponentLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                            let exponent = self.subdata(in: NSRange(location: i, length: exponentLength).toRange()!)
                            i += exponentLength

                            return (modulus, exponent)
                        }
                    }
                }
            }
        }

        return nil
    }

    func dataByPrependingX509RSAHeader() -> Data {
        let result = NSMutableData()

        let encodingLength: Int = (self.count + 1).encodedOctets().count
        let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

        var builder: [CUnsignedChar] = []

        // ASN.1 SEQUENCE
        builder.append(0x30)

        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.count
        let encodedSize = size.encodedOctets()
        builder.append(contentsOf: encodedSize)
        result.append(builder, length: builder.count)
        result.append(OID, length: OID.count)
        builder.removeAll(keepingCapacity: false)

        builder.append(0x03)
        builder.append(contentsOf: (self.count + 1).encodedOctets())
        builder.append(0x00)
        result.append(builder, length: builder.count)
        
        // Actual key bytes
        result.append(self)
        
        return result as Data
    }

    func dataByStrippingX509Header() -> Data {
        var bytes = [CUnsignedChar](repeating: 0, count: self.count)
        (self as NSData).getBytes(&bytes, length:self.count)

        var range = NSRange(location: 0, length: self.count)
        var offset = 0

        // ASN.1 Sequence
        if bytes[offset] == 0x30 {
            offset += 1

            // Skip over length
            let _ = NSInteger(octetBytes: bytes, startIdx: &offset)

            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let slice: [CUnsignedChar] = Array(bytes[offset..<(offset + OID.count)])

            if slice == OID {
                offset += OID.count

                // Type
                if bytes[offset] != 0x03 {
                    return self
                }

                offset += 1

                // Skip over the contents length field
                let _ = NSInteger(octetBytes: bytes, startIdx: &offset)

                // Contents should be separated by a null from the header
                if bytes[offset] != 0x00 {
                    return self
                }

                offset += 1
                range.location += offset
                range.length -= offset
            } else {
                return self
            }
        }

        return self.subdata(in: range.toRange()!)
    }
}
