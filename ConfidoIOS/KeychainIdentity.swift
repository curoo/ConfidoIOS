//
//  Identity.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
//

import Foundation
import Security


public protocol Identity {
    typealias CertificateType : Certificate
    typealias KeyPairType  : KeyPair
    var certificate: CertificateType { get }
    var keyPair: KeyPairType { get }
}

public class IdentityReference {
    public let secItemRef : SecIdentityRef
    public init(reference: SecIdentityRef) {
        self.secItemRef = reference
    }
}

public class IdentitySpecifier : KeychainDescriptor {
    public init(itemLabel: String) {
            super.init(securityClass: .Identity, itemLabel: itemLabel)
    }

    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }
}


//TODO: Identify protocol
public class KeychainIdentity: KeychainItem, KeychainFindable, GenerateKeychainFind {
    public typealias QueryType = IdentityDescriptor
    public typealias ResultType = KeychainIdentity
    public let keyPair : KeychainKeyPair?
    public let certificate : KeychainCertificate?
    public let secIdentity: SecIdentity!

    class func getSecIdentity(SecItemAttributes attributes: NSDictionary) -> SecIdentity {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecIdentityGetTypeID() {
                let secIdentity = (valueRef as! SecIdentity)
                return secIdentity
            }
        }
        fatalError("No CertificateRef found")
    }


    public class func identityFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainIdentity {
        let keyPair = try KeychainKeyPair(SecItemAttributes: attributes)
        let certificate = try KeychainCertificate(SecItemAttributes: attributes)
        let secIdentity = getSecIdentity(SecItemAttributes: attributes)
        return KeychainIdentity(secIdentity: secIdentity, keyPair: keyPair, certificate: certificate)
    }


    public class func identity(matchingDescriptor: IdentityDescriptor) throws -> KeychainIdentity? {
        let keyItem = try Keychain.fetchItem(matchingDescriptor: matchingDescriptor)
        if keyItem is KeychainIdentity {
            return keyItem as? KeychainIdentity
        }
        return nil
    }

/**
    Imports an Identity from pkcs12 Encoded Data
    :param: pkcs12EncodedData
    :param: protectedWithPassphrase
    :param: label An optional label to be associated with the identity when added to the Keychain
    :returns: A TransportIdentity than can be added to the Keychain
*/
    public class func importIdentity(pkcs12EncodedData: NSData, protectedWithPassphrase passPhrase: String, label: String? = nil) throws -> TransportIdentity {
        var options : KeyChainPropertiesData = [ : ]

        options[kSecImportExportPassphrase as String] = passPhrase

        let items = try SecurityWrapper.secPKCS12Import(pkcs12EncodedData, options: options)
        if items.count == 1 {
            let secIdentity : SecIdentity          = items[0][kSecImportItemIdentity as String] as! SecIdentityRef
            let secTrust    : SecTrust             = items[0][kSecImportItemTrust as String] as! SecTrustRef
            let certificateChain: [SecCertificate] = items[0][kSecImportItemCertChain as String] as! [SecCertificateRef]
            return TransportIdentity(secIdentity: secIdentity,secTrust: secTrust, certificates: certificateChain, itemLabel: label)
        }
        fatalError("No SecIdentity Reference returned")
    }

    init(secIdentity: SecIdentity, keyPair: KeychainKeyPair, certificate: KeychainCertificate) {
        self.secIdentity = secIdentity
        self.keyPair = keyPair
        self.certificate = certificate
        super.init(securityClass: .Identity)
    }

}


/**
Container class for an identity in a transportable format
*/
public class TransportIdentity : KeychainDescriptor, SecItemAddable {
    public private(set) var secTrust: SecTrust!
    public private(set) var secIdentity: SecIdentity!
    public private(set) var certificates: [SecCertificate] = []
    let label : String?
    public init(secIdentity: SecIdentity, secTrust: SecTrust, certificates: [SecCertificate], itemLabel: String? = nil) {
        self.label = itemLabel
        super.init(securityClass: SecurityClass.Identity, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secIdentity
        self.secTrust = secTrust
        self.secIdentity = secIdentity
        self.certificates = certificates
    }
    public func addToKeychain() throws -> KeychainIdentity {
        let importDescriptor = IdentityImportDescriptor(identity: self, label: self.label)
        try importDescriptor.secItemAdd()
        let result = try KeychainIdentity.findInKeychain(IdentityDescriptor(identityLabel: self.label))
        return result!
    }
}



public class IdentityImportDescriptor : KeyChainAttributeStorage, SecItemAddable {
    public var attributes : [String : AnyObject] = [ : ]
    public init(identity: TransportIdentity, label: String?) {
        attributes[String(kSecValueRef)] = identity.secIdentity
        if label != nil {
            attributes[String(kSecAttrLabel)] = label!
        }
    }
    public func secItemAdd() throws -> AnyObject? {
        var item : KeyChainPropertiesData = [ : ]
        item += self.attributes
//        item[String(kSecClass)] = SecurityClass.kSecClass(SecurityClass.Identity)
        let itemRef: AnyObject? = try SecurityWrapper.secItemAdd(item)
        return itemRef
    }

}


public class IdentityDescriptor : KeychainDescriptor {
    public init(identityDescriptor: IdentityDescriptor) {
        super.init(descriptor: identityDescriptor)
    }

    public init(identityLabel: String? = nil) {
            super.init(securityClass: .Identity, itemLabel: identityLabel)
    }
}

