//
//  SecurityMappings.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation
import Security

public let kCommonMatchingProperties : Set<SecAttr> = [ .Label ]

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

public let kGenericPasswordMatchingProperties : Set<SecAttr> = [ .Label, .Account, .Service ]


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

public let kInternetPasswordMatchingProperties : Set<SecAttr> = [
    .Label, .Account, .Service ]

public let kInternetPasswordProperties : Set<SecAttr> = [
    .Label, .AccessGroup, .Accessible, .AccessControl,
    .Account, .CreationDate, .ModificationDate, .Description, .Comment, .Creator,
    .AttrType, .IsInvisible, .IsNegative, .Service, .Generic ]

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

public let kCertificateSearchProperties : Set<SecAttr> = [ .Label, .Subject, .SubjectKeyID, .PublicKeyHash ]

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

public let kKeyItemMatchingProperties :     Set<SecAttr> = [ .Label, .ApplicationTag, .ApplicationLabel, .KeyClass, .KeyType, .KeySizeInBits ]

public let kKeyItemProperties : Set<SecAttr> = [
    .Label, .AccessGroup, .Accessible, .AccessControl,
    .KeyClass, .KeyType, .ApplicationLabel, .IsPermanent, .ApplicationTag,
    .KeySizeInBits, .EffectiveKeySize, .CanEncrypt, .CanDecrypt,
    .CanDerive, .CanSign, .CanVerify, .CanWrap, .CanUnwrap  ]

public enum KeychainStatus {
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


public enum SecAttr {
    case Accessible, AccessControl, AccessGroup, CreationDate,  ModificationDate, Description, Comment,
    Creator, AttrType, Label, IsInvisible, IsNegative, Account,
    Service, Generic, SecurityDomain, Server, AttrProtocol, AuthenticationType, Port, Path,
    CertificateType, CertificateEncoding, Subject, Issuer, SerialNumber, SubjectKeyID,
    PublicKeyHash, KeyClass, ApplicationLabel, IsPermanent, ApplicationTag, KeyType,
    KeySizeInBits, EffectiveKeySize, CanEncrypt, CanDecrypt, CanDerive, CanSign,
    CanVerify, CanWrap, CanUnwrap

    static func kSecAttr(attribute: SecAttr) -> CFStringRef {
        return forwardMapping[attribute]!
    }

    static func secAttr(kSecAttr: AnyObject) -> SecAttr? {
        if kSecAttr is CFStringRef {
            let secAttr = kSecAttr as! CFStringRef
            if secAttr == kSecAttrAccessible             { return Accessible }
            if secAttr == kSecAttrAccessControl          { return AccessControl }
            if secAttr == kSecAttrAccessGroup            { return AccessGroup }
            if secAttr == kSecAttrCreationDate           { return CreationDate }
            if secAttr == kSecAttrModificationDate       { return ModificationDate }
            if secAttr == kSecAttrDescription            { return Description }
            if secAttr == kSecAttrComment                { return Comment }
            if secAttr == kSecAttrCreator                { return Creator }
            if secAttr == kSecAttrType                   { return AttrType }
            if secAttr == kSecAttrLabel                  { return Label }
            if secAttr == kSecAttrIsInvisible            { return IsInvisible }
            if secAttr == kSecAttrIsNegative             { return IsNegative }
            if secAttr == kSecAttrAccount                { return Account }
            if secAttr == kSecAttrService                { return Service }
            if secAttr == kSecAttrGeneric                { return Generic }
            if secAttr == kSecAttrSecurityDomain         { return SecurityDomain }
            if secAttr == kSecAttrServer                 { return Server }
            if secAttr == kSecAttrProtocol               { return AttrProtocol }
            if secAttr == kSecAttrAuthenticationType     { return AuthenticationType }
            if secAttr == kSecAttrPort                   { return Port }
            if secAttr == kSecAttrPath                   { return Path }
            if secAttr == kSecAttrCertificateType        { return CertificateType }
            if secAttr == kSecAttrCertificateEncoding    { return CertificateEncoding }
            if secAttr == kSecAttrSubject                { return Subject }
            if secAttr == kSecAttrIssuer                 { return Issuer }
            if secAttr == kSecAttrSerialNumber           { return SerialNumber }
            if secAttr == kSecAttrSubjectKeyID           { return SubjectKeyID }
            if secAttr == kSecAttrPublicKeyHash          { return PublicKeyHash }
            if secAttr == kSecAttrKeyClass               { return KeyClass }
            if secAttr == kSecAttrApplicationLabel       { return ApplicationLabel }
            if secAttr == kSecAttrIsPermanent            { return IsPermanent }
            if secAttr == kSecAttrApplicationTag         { return ApplicationTag }
            if secAttr == kSecAttrKeyType                { return KeyType }
            if secAttr == kSecAttrKeySizeInBits          { return KeySizeInBits }
            if secAttr == kSecAttrEffectiveKeySize       { return EffectiveKeySize }
            if secAttr == kSecAttrCanEncrypt             { return CanEncrypt }
            if secAttr == kSecAttrCanDecrypt             { return CanDecrypt }
            if secAttr == kSecAttrCanDerive              { return CanDerive }
            if secAttr == kSecAttrCanSign                { return CanSign }
            if secAttr == kSecAttrCanVerify              { return CanVerify }
            if secAttr == kSecAttrCanWrap                { return CanWrap }
            if secAttr == kSecAttrCanUnwrap              { return CanUnwrap }
        }
        return nil
    }

    static let forwardMapping: [SecAttr: CFStringRef] = [
        Accessible:          kSecAttrAccessible,
        AccessControl:       kSecAttrAccessControl,
        AccessGroup:         kSecAttrAccessGroup,
        CreationDate:        kSecAttrCreationDate,
        ModificationDate:    kSecAttrModificationDate,
        Description:         kSecAttrDescription,
        Comment:             kSecAttrComment,
        Creator:             kSecAttrCreator,
        AttrType:            kSecAttrType,
        Label:               kSecAttrLabel,
        IsInvisible:         kSecAttrIsInvisible,
        IsNegative:          kSecAttrIsNegative,
        Account:             kSecAttrAccount,
        Service:             kSecAttrService,
        Generic:             kSecAttrGeneric,
        SecurityDomain:      kSecAttrSecurityDomain,
        Server:              kSecAttrServer,
        AttrProtocol:        kSecAttrProtocol,
        AuthenticationType:  kSecAttrAuthenticationType,
        Port:                kSecAttrPort,
        Path:                kSecAttrPath,
        CertificateType:     kSecAttrCertificateType,
        CertificateEncoding: kSecAttrCertificateEncoding,
        Subject:             kSecAttrSubject,
        Issuer:              kSecAttrIssuer,
        SerialNumber:        kSecAttrSerialNumber,
        SubjectKeyID:        kSecAttrSubjectKeyID,
        PublicKeyHash:       kSecAttrPublicKeyHash,
        KeyClass:            kSecAttrKeyClass,
        ApplicationLabel:    kSecAttrApplicationLabel,
        IsPermanent:         kSecAttrIsPermanent,
        ApplicationTag:      kSecAttrApplicationTag,
        KeyType:             kSecAttrKeyType,
        KeySizeInBits:       kSecAttrKeySizeInBits,
        EffectiveKeySize:    kSecAttrEffectiveKeySize,
        CanEncrypt:          kSecAttrCanEncrypt,
        CanDecrypt:          kSecAttrCanDecrypt,
        CanDerive:           kSecAttrCanDerive,
        CanSign:             kSecAttrCanSign,
        CanVerify:           kSecAttrCanVerify,
        CanWrap:             kSecAttrCanWrap,
        CanUnwrap:           kSecAttrCanUnwrap
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

public enum KeyType {
    case RSA, ElypticCurve

    static func kSecAttrKeyType(keyType: KeyType) -> CFStringRef {
        return forwardMapping[keyType]!
    }

    static func keyType(kKeyType: AnyObject) -> KeyType {
        return reverseMapping[kKeyType as! String]!
    }

    static let forwardMapping: [KeyType: CFStringRef] = [
        RSA:             kSecAttrKeyTypeRSA,
        ElypticCurve:    kSecAttrKeyTypeEC
    ]

    static let reverseMapping: [String: KeyType] = [
        kSecAttrKeyTypeRSA as String: RSA,
        kSecAttrKeyTypeEC as String: ElypticCurve
    ]
}

public enum Accessible {
    case WhenUnlock, AfterFirstUnlock, Always, WhenPasscodeSetThisDeviceOnly,
    WhenUnlockedThisDeviceOnly, AfterFirstUnlockThisDeviceOnly, AlwaysThisDeviceOnly
    static func kSecAttrAccessible(accessible: Accessible) -> CFStringRef {
        return mapping[accessible]!
    }

    static let mapping: [Accessible: CFStringRef] = [
        WhenUnlock:                     kSecAttrAccessibleWhenUnlocked,
        AfterFirstUnlock:               kSecAttrAccessibleAfterFirstUnlock,
        Always:                         kSecAttrAccessibleAlways,
        WhenPasscodeSetThisDeviceOnly:  kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        WhenUnlockedThisDeviceOnly:     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        AfterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        AlwaysThisDeviceOnly:           kSecAttrAccessibleAlwaysThisDeviceOnly
    ]
}
