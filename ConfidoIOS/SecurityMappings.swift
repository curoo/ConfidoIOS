//
//  SecurityMappings.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
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

public enum KeychainStatus : ErrorType {
    case UnimplementedError, ParamError, AllocateError, NotAvailableError,
    AuthFailedError, DuplicateItemError, ItemNotFoundError, InteractionNotAllowedError,
    DecodeError, UnknownError, OK

    static func statusFromOSStatus(rawStatus: OSStatus) ->
        KeychainStatus {
            if rawStatus == errSecSuccess {
                return OK
            } else {
                return mapping[rawStatus] ?? .UnknownError
            }
    }

    static func messageForStatus(keychainStatus: KeychainStatus) ->
        String? {
            return messages[keychainStatus]
    }

    static let mapping: [OSStatus: KeychainStatus] = [
        errSecUnimplemented:         .UnimplementedError,
        errSecParam:                 .ParamError,
        errSecAllocate:              .AllocateError,
        errSecNotAvailable:          .NotAvailableError,
        errSecAuthFailed:            .AuthFailedError,
        errSecDuplicateItem:         .DuplicateItemError,
        errSecItemNotFound:          .ItemNotFoundError,
        errSecInteractionNotAllowed: .InteractionNotAllowedError,
        errSecDecode:                .DecodeError,
        errSecSuccess:               .OK
    ]

    static let messages: [KeychainStatus: String] = [
        UnimplementedError:         "Function or operation not implemented.",
        ParamError:                 "One or more parameters passed to the function were not valid.",
        AllocateError:              "Failed to allocate memory.",
        NotAvailableError:          "No trust results are available.",
        AuthFailedError:            "Authorization/Authentication failed.",
        DuplicateItemError:         "The item already exists.",
        ItemNotFoundError:          "The item cannot be found.",
        InteractionNotAllowedError: "Interaction with the Security Server is not allowed.",
        DecodeError:                "Unable to decode the provided data.",
        UnknownError:               "Unknown Error"
    ]
}



public enum SecurityClass {
    case GenericPassword, InternetPassword, Certificate, Key, Identity

    static func kSecClass(securityClass: SecurityClass) -> CFStringRef {
        return forwardMapping[securityClass]!
    }

    static func securityClass(kSecClass: AnyObject) -> SecurityClass? {
        if kSecClass is CFStringRef {
            let secClass = kSecClass as! CFStringRef
            if secClass == kSecClassGenericPassword  { return GenericPassword }
            if secClass == kSecClassInternetPassword { return InternetPassword }
            if secClass == kSecClassCertificate      { return Certificate }
            if secClass == kSecClassKey              { return Key }
            if secClass == kSecClassIdentity         { return Identity }
        }
        return nil
    }

    static let forwardMapping: [SecurityClass: CFStringRef] = [
        GenericPassword:  kSecClassGenericPassword,
        InternetPassword: kSecClassInternetPassword ,
        Certificate:      kSecClassCertificate,
        Key:              kSecClassKey,
        Identity:         kSecClassIdentity
    ]
    static let reverseMapping: [String: SecurityClass] = [
        kSecClassGenericPassword as String:  GenericPassword,
        kSecClassInternetPassword as String: InternetPassword,
        kSecClassCertificate as String:      Certificate,
        kSecClassKey as String:              Key,
        kSecClassIdentity as String:         Identity
    ]

}

public enum KeyClass {
    case SymmetricKey, PublicKey, PrivateKey

    static func kSecAttrKeyClass(keyClass: KeyClass) -> CFStringRef {
        return forwardMapping[keyClass]!
    }

    static func keyClass(kKeyClass: AnyObject?) -> KeyClass {
        if let keyClass = kKeyClass as? Int {
            //kKeyClass comes through as an NSNumber, despite the documentation saying it is a String
            if let reverse = self.reverseMapping[keyClass] {
                return reverse
            }
        }
        else if kKeyClass is NSString {
            let keyClass = kKeyClass as! CFStringRef
            if keyClass == kSecAttrKeyClassSymmetric  { return SymmetricKey }
            if keyClass == kSecAttrKeyClassPublic     { return PublicKey }
            if keyClass == kSecAttrKeyClassPrivate    { return PrivateKey }
        }
        assertionFailure("Unknown keyClass \(kKeyClass!)")
        return PublicKey
    }

    static let forwardMapping: [KeyClass: CFStringRef] = [
        SymmetricKey: kSecAttrKeyClassSymmetric,
        PublicKey:    kSecAttrKeyClassPublic,
        PrivateKey:   kSecAttrKeyClassPrivate
    ]

//    SEC_CONST_DECL (kSecAttrKeyClassPublic, "0");
//    SEC_CONST_DECL (kSecAttrKeyClassPrivate, "1");
//    SEC_CONST_DECL (kSecAttrKeyClassSymmetric, "2");

    static let reverseMapping: [Int: KeyClass] = [
        0: PublicKey,
        1: PrivateKey,
        2: SymmetricKey
    ]
}


public enum KeyType: RawRepresentable {
    case RSA, ElypticCurve

    public init?(rawValue: String) {
        switch rawValue {
        case String(kSecAttrKeyTypeRSA):
            self = RSA
        case String(kSecAttrKeyTypeEC):
            self = ElypticCurve
        default:
            print("Accessible: invalid rawValue provided. Defaulting to KeyType.RSA")
            self = RSA
        }
    }

    public var rawValue: String {
        switch self {
        case .RSA:
            return String(kSecAttrKeyTypeRSA)
        case .ElypticCurve:
            return String(kSecAttrKeyTypeEC)
        }
    }
}



public enum Accessible : RawRepresentable {
    case WhenUnlocked, AfterFirstUnlock, Always,
    WhenPasscodeSetThisDeviceOnly, WhenUnlockedThisDeviceOnly,
    AfterFirstUnlockThisDeviceOnly, AlwaysThisDeviceOnly

    public init?(rawValue: String) {
        if rawValue == String(kSecAttrAccessibleWhenUnlocked) {
            self = WhenUnlocked
        }
        else if rawValue == String(kSecAttrAccessibleAfterFirstUnlock) {
            self = AfterFirstUnlock
        }
        else if rawValue == String(kSecAttrAccessibleAlways) {
            self = Always
        }
        else if rawValue == String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) {
            self = WhenPasscodeSetThisDeviceOnly
        }
        else if rawValue == String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly) {
            self = WhenUnlockedThisDeviceOnly
        }
        else if rawValue == String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) {
            self = AfterFirstUnlockThisDeviceOnly
        }
        else if rawValue == String(kSecAttrAccessibleAlwaysThisDeviceOnly) {
            self = AlwaysThisDeviceOnly
        }
        else {
            return nil
        }
    }

    public var rawValue: String {
        switch self {
        case WhenUnlocked:
            return String(kSecAttrAccessibleWhenUnlocked)
        case AfterFirstUnlock:
            return String(kSecAttrAccessibleAfterFirstUnlock)
        case Always:
            return String(kSecAttrAccessibleAlways)
        case WhenPasscodeSetThisDeviceOnly:
            return String(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        case WhenUnlockedThisDeviceOnly:
            return String(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        case AfterFirstUnlockThisDeviceOnly: 
            return String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        case AlwaysThisDeviceOnly: 
            return String(kSecAttrAccessibleAlwaysThisDeviceOnly)
        }
    }	
}

