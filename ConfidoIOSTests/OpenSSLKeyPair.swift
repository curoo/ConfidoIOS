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


//https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift


private extension NSInteger {
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)];
        }

        // Long form
        let i = (self / 256) + 1
        var len = self
        var result: [CUnsignedChar] = [CUnsignedChar(i + 0x80)]

        for (var j = 0; j < i; j++) {
            result.insert(CUnsignedChar(len & 0xFF), atIndex: 1)
            len = len >> 8
        }

        return result
    }

    init?(octetBytes: [CUnsignedChar], inout startIdx: NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] - 128)

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

private extension NSData {
    convenience init(modulus: NSData, exponent: NSData) {
        // Make sure neither the modulus nor the exponent start with a null byte
        let modulusBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(modulus.bytes), count: modulus.length / sizeof(CUnsignedChar)))
        let exponentBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(exponent.bytes), count: exponent.length / sizeof(CUnsignedChar)))

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
        builder.appendContentsOf(totalLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)

        // Modulus
        builder.append(0x02)
        builder.appendContentsOf(modulusLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)
        data.appendBytes(modulusBytes, length: modulusBytes.count)

        // Exponent
        builder.append(0x02)
        builder.appendContentsOf(exponentLengthOctets)
        data.appendBytes(builder, length: builder.count)
        data.appendBytes(exponentBytes, length: exponentBytes.count)

        self.init(data: data)
    }

    func splitIntoComponents() -> (modulus: NSData, exponent: NSData)? {
        // Get the bytes from the keyData
        let pointer = UnsafePointer<CUnsignedChar>(self.bytes)
        let keyBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start:pointer, count:self.length / sizeof(CUnsignedChar)))

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
            if keyBytes[i++] == 0x02, let modulusLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                let modulus = self.subdataWithRange(NSMakeRange(i, modulusLength))
                i += modulusLength

                // Second should be the exponent
                if keyBytes[i++] == 0x02, let exponentLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
                    let exponent = self.subdataWithRange(NSMakeRange(i, exponentLength))
                    i += exponentLength

                    return (modulus, exponent)
                }
            }
        }

        return nil
    }

    func dataByPrependingX509RSAHeader() -> NSData {
        let result = NSMutableData()

        let encodingLength: Int = (self.length + 1).encodedOctets().count
        let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

        var builder: [CUnsignedChar] = []

        // ASN.1 SEQUENCE
        builder.append(0x30)

        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.length
        let encodedSize = size.encodedOctets()
        builder.appendContentsOf(encodedSize)
        result.appendBytes(builder, length: builder.count)
        result.appendBytes(OID, length: OID.count)
        builder.removeAll(keepCapacity: false)

        builder.append(0x03)
        builder.appendContentsOf((self.length + 1).encodedOctets())
        builder.append(0x00)
        result.appendBytes(builder, length: builder.count)

        // Actual key bytes
        result.appendData(self)

        return result as NSData
    }

    func dataByStrippingX509RSAHeader() -> NSData {
        var bytes = [CUnsignedChar](count: self.length, repeatedValue: 0)
        self.getBytes(&bytes, length:self.length)

        var range = NSRange(location: 0, length: self.length)
        var offset = 0

        // ASN.1 Sequence
        if bytes[offset++] == 0x30 {
            // Skip over length
            let _ = NSInteger(octetBytes: bytes, startIdx: &offset)

            // PKCS #1 rsaEncryption szOID_RSA_RSA 1.2.840.113549.1.1.1

            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let slice: [CUnsignedChar] = Array(bytes[offset..<(offset + OID.count)])

            if slice == OID {
                offset += OID.count

                // Type
                if bytes[offset++] != 0x03 {
                    return self
                }

                // Skip over the contents length field
                let _ = NSInteger(octetBytes: bytes, startIdx: &offset)

                // Contents should be separated by a null from the header
                if bytes[offset++] != 0x00 {
                    return self
                }
                
                range.location += offset
                range.length -= offset
            } else {
                return self
            }
        }
        
        return self.subdataWithRange(range)
    }
}