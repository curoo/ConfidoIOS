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
        attributes[.KeyClass] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

    public override init(keychainAttributes attributes: NSDictionary) {
        super.init(keychainAttributes: attributes)
        self.attributes[.KeyClass] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

}

public class PrivateKey : KeychainKey {
    override public init(specification: KeySpecification, keyRef: SecKey) {
        super.init(specification: specification, keyRef: keyRef)
        attributes[.KeyClass] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }

    public override init(keychainAttributes attributes: NSDictionary) {
        super.init(keychainAttributes: attributes)
        self.attributes[.KeyClass] = KeyClass.kSecAttrKeyClass(.PrivateKey)
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

    public let itemProperties   = kKeyItemProperties
}


//https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift


private extension NSInteger {
    func encodedOctets() -> [CUnsignedChar] {
        // Short form
        if self < 128 {
            return [CUnsignedChar(self)];
        }

        // Long form
        var i = (self / 256) + 1
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
        var modulusBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(modulus.bytes), count: modulus.length / sizeof(CUnsignedChar)))
        var exponentBytes = [CUnsignedChar](UnsafeBufferPointer<CUnsignedChar>(start: UnsafePointer<CUnsignedChar>(exponent.bytes), count: exponent.length / sizeof(CUnsignedChar)))

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
        builder.extend(totalLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)

        // Modulus
        builder.append(0x02)
        builder.extend(modulusLengthOctets)
        data.appendBytes(builder, length: builder.count)
        builder.removeAll(keepCapacity: false)
        data.appendBytes(modulusBytes, length: modulusBytes.count)

        // Exponent
        builder.append(0x02)
        builder.extend(exponentLengthOctets)
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
        if let totalLength = NSInteger(octetBytes: keyBytes, startIdx: &i) {
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

    func dataByPrependingX509Header() -> NSData {
        let result = NSMutableData()

        let encodingLength: Int = count((self.length + 1).encodedOctets())
        let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

        var builder: [CUnsignedChar] = []

        // ASN.1 SEQUENCE
        builder.append(0x30)

        // Overall size, made of OID + bitstring encoding + actual key
        let size = OID.count + 2 + encodingLength + self.length
        let encodedSize = size.encodedOctets()
        builder.extend(encodedSize)
        result.appendBytes(builder, length: builder.count)
        result.appendBytes(OID, length: OID.count)
        builder.removeAll(keepCapacity: false)

        builder.append(0x03)
        builder.extend((self.length + 1).encodedOctets())
        builder.append(0x00)
        result.appendBytes(builder, length: builder.count)

        // Actual key bytes
        result.appendData(self)

        return result as NSData
    }

    func dataByStrippingX509Header() -> NSData {
        var bytes = [CUnsignedChar](count: self.length, repeatedValue: 0)
        self.getBytes(&bytes, length:self.length)

        var range = NSRange(location: 0, length: self.length)
        var offset = 0

        // ASN.1 Sequence
        if bytes[offset++] == 0x30 {
            // Skip over length
            let _ = NSInteger(octetBytes: bytes, startIdx: &offset)

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