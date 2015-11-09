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
    public typealias QueryType = CertificateDescriptor
    public typealias ResultType = KeychainCertificate
    public private(set) var secCertificate: SecCertificate! = nil
    public private(set) var subject: String = ""

    public class func keychainCertificateFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainCertificate {
        return try KeychainCertificate(SecItemAttributes: attributes)
    }

    public class func certificate(derEncodedCertificateData: NSData, itemLabel: String? = nil) throws -> TransportCertificate {
        let secCertificate = SecCertificateCreateWithData(nil, derEncodedCertificateData)
        if secCertificate != nil {
            return TransportCertificate(secCertificate: secCertificate!, itemLabel: itemLabel)
        }
        throw KeychainError.InvalidCertificateData
    }

    class func getSecCertificate(SecItemAttributes attributes: NSDictionary) throws -> SecCertificate {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecCertificateGetTypeID() {
                return (valueRef as! SecCertificate)
            } else if CFGetTypeID(valueRef) == SecIdentityGetTypeID() {
                let secIdentity = (valueRef as! SecIdentity)
                return try certificateRef(secIdentity)
            }

        }
        fatalError("No CertificateRef found")
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Certificate, SecItemAttributes: attributes)
        self.secCertificate = try KeychainCertificate.getSecCertificate(SecItemAttributes: attributes)
        self.subject = SecCertificateCopySubjectSummary(self.secCertificate) as String
    }

}

public class CertificateDescriptor : KeychainDescriptor {
    public init(certificateDescriptor: CertificateDescriptor) {
        super.init(descriptor: certificateDescriptor)
    }

    public init(certificateLabel: String) {
        super.init(securityClass: .Certificate, itemLabel: certificateLabel)
    }
}


/**
Container class for an identity in a transportable format
*/
public class TransportCertificate : KeychainDescriptor, SecItemAddable, Certificate {
    public private(set) var subject: String
    public private(set) var secCertificate: SecCertificate!
    let label : String?
    public init(secCertificate: SecCertificate, itemLabel: String? = nil) {
        self.secCertificate = secCertificate
        self.label = itemLabel
        self.subject = SecCertificateCopySubjectSummary(secCertificate) as String
        super.init(securityClass: SecurityClass.Certificate, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secCertificate

    }
    public func addToKeychain() throws -> KeychainCertificate? {
        try self.secItemAdd()
        if label != nil {
            return try KeychainCertificate.findInKeychain(CertificateDescriptor(certificateLabel: self.label!))!
        }
        return nil
    }

}

