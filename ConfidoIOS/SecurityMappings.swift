//
//  SecurityMappings.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//
//

import Foundation
import Security

public let kCommonMatchingProperties : Set<String> = [ String(kSecAttrLabel) ]

//kSecClassGenericPassword item attributes:
//  * kSecAttrAccessible
//  * kSecAttrAccessControl
//  * kSecAttrAccessGroup
//    kSecAttrCreationDate
//    kSecAttrModificationDate
//    kSecAttrDescription
//    kSecAttrComment
//    kSecAttrCreator
//    kSecAttrType
//  * kSecAttrLabel
//    kSecAttrIsInvisible
//    kSecAttrIsNegative
//    kSecAttrAccount
//    kSecAttrService
//    kSecAttrGeneric

public let kGenericPasswordMatchingProperties : Set<String> = [ String(kSecAttrLabel), String(kSecAttrAccount), String(kSecAttrService) ]


//kSecClassInternetPassword item attributes:
//  * kSecAttrAccessible
//  * kSecAttrAccessControl
//  * kSecAttrAccessGroup
//    kSecAttrCreationDate
//    kSecAttrModificationDate
//    kSecAttrDescription
//    kSecAttrComment
//    kSecAttrCreator
//    kSecAttrType
//  * kSecAttrLabel
//    kSecAttrIsInvisible
//    kSecAttrIsNegative
//    kSecAttrAccount
//    kSecAttrSecurityDomain
//    kSecAttrServer
//    kSecAttrProtocol
//    kSecAttrAuthenticationType
//    kSecAttrPort
//    kSecAttrPath

public let kInternetPasswordMatchingProperties : Set<String> = [ String(kSecAttrLabel), String(kSecAttrAccount), String(kSecAttrService) ]

//public let kInternetPasswordProperties : Set<String> = [
//    String(kSecAttrLabel), String(kSecAttrAccessGroup), String(kSecAttrAccessible), String(kSecAttrAccessControl),
//    String(kSecAttrAccount), String(kSecAttrCreationDate), String(kSecAttrModificationDate), String(kSecAttrDescription), String(kSecAttrComment), String(kSecAttrCreator),
//    String(kSecAttrType), String(kSecAttrIsInvisible), String(kSecAttrIsNegative), String(kSecAttrService), String(kSecAttrGeneric) ]

//kSecClassCertificate item attributes:
//  * kSecAttrAccessible
//  * kSecAttrAccessControl
//  * kSecAttrAccessGroup
//    kSecAttrCertificateType
//    kSecAttrCertificateEncoding
//  * kSecAttrLabel
//    kSecAttrSubject
//    kSecAttrIssuer
//    kSecAttrSerialNumber
//    kSecAttrSubjectKeyID
//    kSecAttrPublicKeyHash
//

public let kCertificateSearchProperties : Set<String> = [ String(kSecAttrLabel), String(kSecAttrSubject), String(kSecAttrSubjectKeyID), String(kSecAttrPublicKeyHash) ]

//kSecClassIdentity item attributes:
//  Since an identity is the combination of a private key and a
//  certificate, this class shares attributes of both kSecClassKey and
//  kSecClassCertificate.


//kSecClassKey item attributes:
//  * kSecAttrAccessible
//  * kSecAttrAccessControl
//  * kSecAttrAccessGroup
//    kSecAttrKeyClass
//  * kSecAttrLabel
//    kSecAttrApplicationLabel
//    kSecAttrIsPermanent
//    kSecAttrApplicationTag
//    kSecAttrKeyType
//    kSecAttrKeySizeInBits
//    kSecAttrEffectiveKeySize
//    kSecAttrCanEncrypt
//    kSecAttrCanDecrypt
//    kSecAttrCanDerive
//    kSecAttrCanSign
//    kSecAttrCanVerify
//    kSecAttrCanWrap
//    kSecAttrCanUnwrap

public let kKeyItemMatchingProperties :     Set<String> = [ String(kSecAttrLabel), String(kSecAttrApplicationTag),
    String(kSecAttrApplicationLabel), String(kSecAttrKeyClass), String(kSecAttrKeyType), String(kSecAttrKeySizeInBits) ]

//public let kKeyItemProperties : Set<String> = [
//    .Label, .AccessGroup, .Accessible, .AccessControl,
//    .KeyClass, .KeyType, .ApplicationLabel, .IsPermanent, .ApplicationTag,
//    .KeySizeInBits, .EffectiveKeySize, .CanEncrypt, .CanDecrypt,
//    .CanDerive, .CanSign, .CanVerify, .CanWrap, .CanUnwrap  ]

public enum KeychainStatus : LocalizedError {
    case unimplementedError, paramError, allocateError, notAvailableError,
    authFailedError, duplicateItemError, itemNotFoundError, interactionNotAllowedError,
    decodeError, unknownError, ok

    public var errorDescription: String? {
        return KeychainStatus.messageForStatus(self)
    }

    static func statusFromOSStatus(_ rawStatus: OSStatus) ->
        KeychainStatus {
            if rawStatus == errSecSuccess {
                return ok
            } else {
                return mapping[rawStatus] ?? .unknownError
            }
    }

    static func messageForStatus(_ keychainStatus: KeychainStatus) ->
        String? {
            return messages[keychainStatus]
    }

    static let mapping: [OSStatus: KeychainStatus] = [
        errSecUnimplemented:         .unimplementedError,
        errSecParam:                 .paramError,
        errSecAllocate:              .allocateError,
        errSecNotAvailable:          .notAvailableError,
        errSecAuthFailed:            .authFailedError,
        errSecDuplicateItem:         .duplicateItemError,
        errSecItemNotFound:          .itemNotFoundError,
        errSecInteractionNotAllowed: .interactionNotAllowedError,
        errSecDecode:                .decodeError,
        errSecSuccess:               .ok
    ]

    static let messages: [KeychainStatus: String] = [
        unimplementedError:         "Function or operation not implemented.",
        paramError:                 "One or more parameters passed to the function were not valid.",
        allocateError:              "Failed to allocate memory.",
        notAvailableError:          "No trust results are available.",
        authFailedError:            "Authorization/Authentication failed.",
        duplicateItemError:         "The item already exists.",
        itemNotFoundError:          "The item cannot be found.",
        interactionNotAllowedError: "Interaction with the Security Server is not allowed.",
        decodeError:                "Unable to decode the provided data.",
        unknownError:               "Unknown Error"
    ]
}



public enum SecurityClass {
    case genericPassword, internetPassword, certificate, key, identity

    static func kSecClass(_ securityClass: SecurityClass) -> CFString {
        return forwardMapping[securityClass]!
    }

    static func securityClass(_ secClass: AnyObject) -> SecurityClass? {
        guard let secClass = secClass as? NSString else { return nil }
        if secClass == kSecClassGenericPassword  { return genericPassword }
        if secClass == kSecClassInternetPassword { return internetPassword }
        if secClass == kSecClassCertificate      { return certificate }
        if secClass == kSecClassKey              { return key }
        if secClass == kSecClassIdentity         { return identity }
        return nil
    }

    static let forwardMapping: [SecurityClass: CFString] = [
        genericPassword:  kSecClassGenericPassword,
        internetPassword: kSecClassInternetPassword ,
        certificate:      kSecClassCertificate,
        key:              kSecClassKey,
        identity:         kSecClassIdentity
    ]
    static let reverseMapping: [String: SecurityClass] = [
        kSecClassGenericPassword as String:  genericPassword,
        kSecClassInternetPassword as String: internetPassword,
        kSecClassCertificate as String:      certificate,
        kSecClassKey as String:              key,
        kSecClassIdentity as String:         identity
    ]

}

public enum KeyClass {
    case symmetricKey, publicKey, privateKey

    static func kSecAttrKeyClass(_ keyClass: KeyClass) -> CFString {
        return forwardMapping[keyClass]!
    }

    static func keyClass(_ kKeyClass: AnyObject?) -> KeyClass {
        if let keyClass = kKeyClass as? Int {
            //kKeyClass comes through as an NSNumber, despite the documentation saying it is a String
            if let reverse = self.reverseMapping[keyClass] {
                return reverse
            }
        }
        else if kKeyClass is NSString {
            let keyClass = kKeyClass as! CFString
            if keyClass == kSecAttrKeyClassSymmetric  { return symmetricKey }
            if keyClass == kSecAttrKeyClassPublic     { return publicKey }
            if keyClass == kSecAttrKeyClassPrivate    { return privateKey }
        }
        assertionFailure("Unknown keyClass \(kKeyClass!)")
        return publicKey
    }

    static let forwardMapping: [KeyClass: CFString] = [
        symmetricKey: kSecAttrKeyClassSymmetric,
        publicKey:    kSecAttrKeyClassPublic,
        privateKey:   kSecAttrKeyClassPrivate
    ]

//    SEC_CONST_DECL (kSecAttrKeyClassPublic, "0");
//    SEC_CONST_DECL (kSecAttrKeyClassPrivate, "1");
//    SEC_CONST_DECL (kSecAttrKeyClassSymmetric, "2");

    static let reverseMapping: [Int: KeyClass] = [
        0: publicKey,
        1: privateKey,
        2: symmetricKey
    ]
}


public enum KeyType: RawRepresentable {
    case rsa, elypticCurve

    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyTypeRSA):
            self = .rsa
        case String(kSecAttrKeyTypeEC):
            self = .elypticCurve
        default:
            print("Accessible: invalid rawValue provided. Defaulting to KeyType.RSA")
            self = .rsa
        }
    }

    public var rawValue: String {
        switch self {
        case .rsa:
            return String(kSecAttrKeyTypeRSA)
        case .elypticCurve:
            return String(kSecAttrKeyTypeEC)
        }
    }
    public func signatureMaxSize(_ keySize: Int) -> Int {
        switch self {
        case .rsa: return keySize / 8
        //Overhead should not be more than ~16 bytes, plus twice the number of EC field size of course (for example, for SECP256 it will be 256/8=32, 32*2 + 16 bytes ~ 80 bytes).
        case .elypticCurve: return 80
        }
    }
}



public enum Accessible : RawRepresentable {
    case whenUnlocked, afterFirstUnlock, always,
    whenPasscodeSetThisDeviceOnly, whenUnlockedThisDeviceOnly,
    afterFirstUnlockThisDeviceOnly, alwaysThisDeviceOnly

    public init?(rawValue: String) {
        if rawValue == String(kSecAttrAccessibleWhenUnlocked) {
            self = .whenUnlocked
        }
        else if rawValue == String(kSecAttrAccessibleAfterFirstUnlock) {
            self = .afterFirstUnlock
        }
        else if rawValue == String(kSecAttrAccessibleAlways) {
            self = .always
        }
        else if rawValue == String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
            self = .whenPasscodeSetThisDeviceOnly
        }
        else if rawValue == String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly) {
            self = .whenUnlockedThisDeviceOnly
        }
        else if rawValue == String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) {
            self = .afterFirstUnlockThisDeviceOnly
        }
        else if rawValue == String(kSecAttrAccessibleAlwaysThisDeviceOnly) {
            self = .alwaysThisDeviceOnly
        }
        else {
            return nil
        }
    }

    public var rawValue: String {
        switch self {
        case .whenUnlocked:
            return String(kSecAttrAccessibleWhenUnlocked)
        case .afterFirstUnlock:
            return String(kSecAttrAccessibleAfterFirstUnlock)
        case .always:
            return String(kSecAttrAccessibleAlways)
        case .whenPasscodeSetThisDeviceOnly:
            return String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        case .whenUnlockedThisDeviceOnly:
            return String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        case .afterFirstUnlockThisDeviceOnly: 
            return String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        case .alwaysThisDeviceOnly: 
            return String(kSecAttrAccessibleAlwaysThisDeviceOnly)
        }
    }	
}

