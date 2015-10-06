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
    public typealias QueryType = TransportIdentity
    public typealias ResultType = KeychainIdentity
//    public let keyPair : KeychainKeyPair
//    public let certificate : KeychainCertificate

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
        throw KeychainError.NoSecIdentityReference
    }
}


/**
Container class for an identity in a transportable format
*/
public class TransportIdentity : KeychainDescriptor, SecItemAddable {
    public private(set) var secTrust: SecTrust!
    public private(set) var secIdentity: SecIdentity!
    public private(set) var certificates: [SecCertificate] = []
    public init(secIdentity: SecIdentity, secTrust: SecTrust, certificates: [SecCertificate], itemLabel: String? = nil) {
        super.init(securityClass: SecurityClass.Identity, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secIdentity
        self.secTrust = secTrust
        self.secIdentity = secIdentity
        self.certificates = certificates
    }
    public func addToKeychain() throws -> KeychainIdentity {
        try self.secItemAdd()
        return try KeychainIdentity.findInKeychain(self)!
    }
}