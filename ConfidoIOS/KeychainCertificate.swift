//
//  Certificate.swift
//
//  Created by Rudolph van Graan on 23/08/2015.
//

import Foundation


public protocol Certificate {
    var secCertificate: SecCertificate! { get }
    var subject: String { get }
    func trustPoint(policy: TrustPolicy, additionalCertificates: [Certificate]) throws -> TrustPoint
}

public protocol RootCACertificate : Certificate { }
public protocol IntermediateCACertificate: Certificate { }
public protocol ClientAuthenticationCertificate: Certificate { }

public class KeychainCertificate : KeychainItem,
    Certificate, KeychainCertificateClassProperties, KeychainFindable, GenerateKeychainFind {
    public typealias QueryType = TransportCertificate
    public typealias ResultType = KeychainCertificate
    public private(set) var secCertificate: SecCertificate! = nil
    public private(set) var subject: String = ""

    public class func keychainCertificateFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainCertificate {
        return try KeychainCertificate(SecItemAttributes: attributes)
    }

    public class func certificate(derEncodedCertificateData: NSData) throws -> TransportCertificate {
        let secCertificate = SecCertificateCreateWithData(nil, derEncodedCertificateData)
        if secCertificate != nil {
            return TransportCertificate(secCertificate: secCertificate!)
        }
        throw KeychainError.InvalidCertificateData
    }

    class func getSecCertificate(SecItemAttributes attributes: NSDictionary) throws -> SecCertificate {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecCertificateGetTypeID() {
                return (valueRef as! SecCertificate)
            }
        }
        throw KeychainError.NoSecCertificateReference
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Certificate, SecItemAttributes: attributes)
        self.secCertificate = try KeychainCertificate.getSecCertificate(SecItemAttributes: attributes)
        self.subject = SecCertificateCopySubjectSummary(self.secCertificate) as String
    }

}

/**
Container class for an identity in a transportable format
*/
public class TransportCertificate : KeychainDescriptor, SecItemAddable, Certificate {
    public private(set) var subject: String
    public private(set) var secCertificate: SecCertificate!
    public init(secCertificate: SecCertificate, itemLabel: String? = nil) {
        self.secCertificate = secCertificate
        self.subject = SecCertificateCopySubjectSummary(secCertificate) as String
        super.init(securityClass: SecurityClass.Certificate, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secCertificate

    }
    public func addToKeychain() throws -> KeychainCertificate {
        try self.secItemAdd()
        return try KeychainCertificate.findInKeychain(self)!
    }

}

