//
//  TrustEvaluationPoint.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 15/09/2015.
//

import Foundation
import Security


public enum TrustResult: RawRepresentable, CustomStringConvertible, ErrorType {
    case Invalid, Proceed,
        Deny, Unspecified, RecoverableTrustFailure,
        FatalTrustFailure, OtherError

    public static let allValues: [TrustResult] =
    [Invalid, Proceed,
        Deny, Unspecified, RecoverableTrustFailure,
        FatalTrustFailure, OtherError]

    public init?(rawValue: Int) {
        if rawValue == kSecTrustResultInvalid                        { self = Invalid }
        else if rawValue == kSecTrustResultProceed                 { self = Proceed }
        else if rawValue == kSecTrustResultDeny                    { self = Deny}
        else if rawValue == kSecTrustResultUnspecified             { self = Unspecified}
        else if rawValue == kSecTrustResultRecoverableTrustFailure { self = RecoverableTrustFailure}
        else if rawValue == kSecTrustResultFatalTrustFailure       { self = FatalTrustFailure}
        else if rawValue == kSecTrustResultOtherError              { self = OtherError}
        else {
            return nil
        }
    }

    public var rawValue: Int {
        switch self {
        case Invalid:                  return kSecTrustResultInvalid
        case Proceed:                  return kSecTrustResultProceed
        case Deny:                     return kSecTrustResultDeny
        case Unspecified:              return kSecTrustResultUnspecified
        case RecoverableTrustFailure:  return kSecTrustResultRecoverableTrustFailure
        case OtherError:               return kSecTrustResultOtherError
        default: return kSecTrustResultOtherError
        }
    }

    public var description : String {
        switch self {
        case Invalid:                  return "Invalid"
        case Proceed:                  return "Proceed"
        case Deny:                     return "Deny"
        case Unspecified:              return "Unspecified"
        case RecoverableTrustFailure:  return "RecoverableTrustFailure"
        default:                       return "OtherError"
        }
    }
}


func trustEnsureOK(status: OSStatus) throws {
    if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
}


public enum TrustPolicy {
    case Generic
    case SSLClient(name: String?)
    case SSLServer(hostname: String?)
}

extension Certificate where Self:Certificate {
    public func trustPoint(policy: TrustPolicy, additionalCertificates certificates: [Certificate]) throws -> TrustPoint {
        let trustPolicies: [ SecPolicy]
        switch policy {
        case .Generic:                 trustPolicies = [SecPolicyCreateBasicX509()]
        case .SSLClient(let name):     trustPolicies = [SecPolicyCreateSSL(false, name)]
        case .SSLServer(let hostname): trustPolicies = [SecPolicyCreateSSL(true, hostname)]
        }

        let certificateRefs = certificates.map { $0.secCertificate } + [self.secCertificate]
        var secTrustResult : SecTrust? = nil
        try trustEnsureOK(SecTrustCreateWithCertificates(certificateRefs, trustPolicies, &secTrustResult))
        return try CertificateTrustPoint(secTrust: secTrustResult!)
    }
}

public protocol Trustable {
    var secTrust : SecTrust { get }
}


public protocol TrustPoint {
    var secTrust : SecTrust { get }
    func ensureTrusted() throws
    func ensureTrusted(trustAnchor: TrustAnchor) throws
    func evaluateTrust() throws -> TrustResult
    func evaluateTrust(trustAnchor: TrustAnchor) throws -> TrustResult
}

public struct CertificateTrustPoint: TrustPoint {
    public private(set) var secTrust: SecTrust
    public init(secTrust: SecTrust) throws {
        self.secTrust = secTrust
    }

    /**
    Ensures that the TrustPoint is trusted, otherwise throws a TrustResult Exception
    */
    public func ensureTrusted() throws {
        let result = try self.evaluateTrust()
        if result == TrustResult.Proceed || result == TrustResult.Unspecified {
            return
        }
        throw result
    }

    /**
    Ensures that the TrustPoint is trusted against trustAnchor, otherwise throws a TrustResult Exception
    */
    public func ensureTrusted(trustAnchor: TrustAnchor) throws {
        let result = try self.evaluateTrust(trustAnchor)
        if result == TrustResult.Proceed || result == TrustResult.Unspecified {
            return
        }
        throw result
    }

    /**
    Evaluations the trust of the TrustPoint against the built-in anchors
    */
    public func evaluateTrust() throws -> TrustResult {
        try setTrustAnchorCertificates([])
        try setTrustAnchorCertificatesOnly(false)
        return try evaluateSecTrust()
    }

    /**
    Evaluates the trust of the TrustPoint against a TrustAnchor
    */
    public func evaluateTrust(trustAnchor: TrustAnchor) throws -> TrustResult {
        if trustAnchor.anchorCertificate != nil {
            try setTrustAnchorCertificates([trustAnchor.anchorCertificate])
        }
        try setTrustAnchorCertificatesOnly(true)
        return try evaluateSecTrust()
    }

    func evaluateSecTrust() throws -> TrustResult {
        var secTrustResultType : SecTrustResultType = 0
        try trustEnsureOK(SecTrustEvaluate(secTrust, &secTrustResultType))
        let trustResult = TrustResult(rawValue: Int(secTrustResultType))!
        if trustResult == .Proceed || trustResult == .Unspecified {
            return trustResult
        } else if trustResult == TrustResult.RecoverableTrustFailure {
            return TrustResult.Deny
        }
        throw KeychainError.TrustError(trustResult: trustResult, reason: getLastTrustError())
    }


    func getTrustExceptions() -> NSData  {
        return SecTrustCopyExceptions(secTrust)
    }

    func setTrustAnchorCertificates(anchors: [Certificate]) throws {
        let anchorRefs: [SecCertificate] = anchors.map { $0.secCertificate }
        try trustEnsureOK(SecTrustSetAnchorCertificates(secTrust, anchorRefs))
    }

    func setTrustAnchorCertificatesOnly(only: Bool) throws {
        try trustEnsureOK(SecTrustSetAnchorCertificatesOnly(secTrust, only))
    }

    func getLastTrustError() -> String? {
        let properties : NSArray! = SecTrustCopyProperties(secTrust)
        for validatedCertificate in properties {
            let propDict = validatedCertificate as! [ String : String]
            if let errorMessage = propDict["value"] {
                // There is no constant in the APIs for this, only kSecPropertyTypeTitle and kSecPropertyTypeError defined
                return errorMessage
            }
        }
        return nil
    }
}



public class TrustAnchor {
    let name : String
    public private(set) var anchorCertificate: Certificate! = nil
    let parentTrustAnchor: TrustAnchor?

    init(parentTrustAnchor: TrustAnchor?, anchorCertificate: Certificate?, name: String? = nil) {
        self.parentTrustAnchor = parentTrustAnchor
        self.anchorCertificate = anchorCertificate
        if name != nil {
            self.name = name!
        } else if anchorCertificate != nil {
            self.name = anchorCertificate!.subject
        } else {
            self.name = "Unspecified"
        }
    }

    /**
    Constructs an empty trust anchor
    */
    public convenience init(name: String) {
        self.init(parentTrustAnchor: nil, anchorCertificate: nil, name: name)
    }
    /**
    Creates a new root TrustAnchor anchored on a certificate
    :param: name A name for the trust anchor
    */
    public convenience init(anchorCertificate: Certificate, name: String? = nil) {
        self.init(parentTrustAnchor: nil, anchorCertificate: anchorCertificate, name: name)
    }

    /*
    Extends the trust anchor. Throws <...> if the certificate cannot be verified under this trust anchor.
    :param: certificate The certificate with which to extend the trust anchor
    :param: name The name of the new TrustAnchor
    :returns: A new TrustAnchor anchored on the current anchor
    */
    public func extendAnchor(certificate: Certificate, name: String? = nil) throws -> TrustAnchor {
        let trust = try certificate.trustPoint(TrustPolicy.Generic,additionalCertificates:[])
        try trust.ensureTrusted(self)
        return TrustAnchor(parentTrustAnchor: self, anchorCertificate: certificate, name: name)
    }

    // Recursively construct the certificate chain from which this certificate derives
    public var certificateChain: [Certificate] {
        get {
            var certificates : [ Certificate ] = []
            if anchorCertificate != nil {
                certificates = [anchorCertificate]
            }
            if parentTrustAnchor != nil {
                certificates.appendContentsOf(parentTrustAnchor!.certificateChain)
            }
            return certificates
        }
    }
}
