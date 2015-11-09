//
//  KeyChainItem.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 18/08/2015.
//
//

import Foundation
import Security



// Update -> Add writers for functions, populate separate dictionary, something calls update

/**
Abstract Item that has a securityClass and attributes. Two classes derive from it.
KeychainItem that represents actual objects in the IOS Keychain and KeychainProperties that describe
the attributes of either a IOS Keychain search (the input dictionary) or the attributes of an object (such as a KeychainKey that could be generated or imported.
*/
public class AbstractItem: KeychainItemClass, KeyChainAttributeStorage {
    public private(set) var securityClass: SecurityClass
    //A dictionary of IOS Keychain attributes keyed by their kSecAttr constants and stored in the format the IOS Keychain requires them
    public var attributes : [String : AnyObject] = [ : ]

    public init(securityClass: SecurityClass) {
        self.securityClass = securityClass
    }

    init(securityClass: SecurityClass, byCopyingAttributes attributes: KeyChainAttributeStorage? ) {
        self.securityClass = securityClass
        self.initAttributes(attributes)
    }

    // Initialises the AbstractItem with the contents from an IOS Keychain Attribute Dictionary
    init(securityClass: SecurityClass, SecItemAttributes attributes: SecItemAttributes) {
        if let secClass: AnyObject = attributes[String(kSecClass)] {
            self.securityClass = SecurityClass.securityClass(secClass)!
        } else {
            self.securityClass = securityClass
        }
        self.initAttributes(attributes)
    }

    func initAttributes(attributes: KeyChainAttributeStorage?) {
        if attributes != nil {
            self.attributes = attributes!.attributes
        }
    }

    func initAttributes(keychainAttributes: NSDictionary) {
        for (key, object) in keychainAttributes {
            // -TODO: This method should only copy the attributes that belongs to the item and not everything as yet. Some types (KeychainIdentity is composed of KeychainCertificate and the KeychainIdentify object should not store the KeychainCertificate's properties, etc.
            if let key = key as? String {
                attributes[key] = object
            }
        }
    }
}

public class KeychainItem: AbstractItem, KeychainCommonClassProperties {
    public class func itemFromAttributes(securityClass: SecurityClass, SecItemAttributes attributes: SecItemAttributes) throws -> KeychainItem {
        switch securityClass {
        case .Identity: return try KeychainIdentity.identityFromAttributes(SecItemAttributes: attributes)
        case .Key: return try KeychainKey.keychainKeyFromAttributes(SecItemAttributes: attributes)
        case .Certificate : return try KeychainCertificate.keychainCertificateFromAttributes(SecItemAttributes: attributes)
        default: throw KeychainError.UnimplementedSecurityClass
        }
    }

    public override init(securityClass: SecurityClass) {
        super.init(securityClass: securityClass)
    }

    override init(securityClass: SecurityClass, byCopyingAttributes attributes: KeyChainAttributeStorage? ) {
        super.init(securityClass: securityClass, byCopyingAttributes: attributes)
    }

    override init(securityClass: SecurityClass, SecItemAttributes attributes: SecItemAttributes) {
        super.init(securityClass: securityClass, SecItemAttributes: attributes)
    }

    public func specifierMatchingProperties() -> Set<String> {
        return kCommonMatchingProperties
    }
}

public class KeychainDescriptor : AbstractItem, KeychainMatchable {
    /**
    Initialises keychain properties from a KeychainItem

    :param: keychainItem

    :returns: a new instance of KeychainDescriptor.
    */
    public init(keychainItem: KeychainItem) {
        super.init(securityClass: keychainItem.securityClass)
        for matchingProperty in keychainItem.specifierMatchingProperties() {
            if let value: AnyObject = keychainItem[matchingProperty] {
                attributes[matchingProperty] = value
            }
        }
    }

    public init(descriptor: KeychainDescriptor) {
        super.init(securityClass: descriptor.securityClass)
        self.attributes = descriptor.attributes
    }

    override init(securityClass: SecurityClass, byCopyingAttributes attributes: KeyChainAttributeStorage? ) {
        super.init(securityClass: securityClass, byCopyingAttributes: attributes)
    }


    public init(securityClass: SecurityClass, itemLabel: String? = nil) {
        super.init(securityClass: securityClass)
        if (itemLabel != nil) {
            attributes[String(kSecAttrLabel)] = itemLabel
        }
    }

    /**
    Provides the dictionary of IOS Keychain attributes that will be used to match IOS Keychain Items against. This is the dictionary that is passed to SecItemCopyMatching()

    :returns: a dictionary of IOS Keychain Attributes.
    */
    //TODO: Rename this to iosKeychainMatchDictionary()
    public func keychainMatchPropertyValues() -> [ String: AnyObject ] {
        var dictionary : [ String : AnyObject] = [ : ]
        dictionary[String(kSecClass)] = SecurityClass.kSecClass(securityClass)
        for (attribute, value) in attributes {
            dictionary[attribute] = value
        }
        return dictionary
    }
}

