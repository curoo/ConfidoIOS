//
//  KeychainProtocol.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 11/09/2015.
//  Copyright © 2015 Curoo Limited. All rights reserved.
//

import Foundation


public protocol KeyChainAttributeStorage {
    var attributes : [String : AnyObject] { get }
    subscript(attribute: String) -> AnyObject? { get }
}


extension KeyChainAttributeStorage where Self : KeyChainAttributeStorage {
    public subscript(attribute: String) -> AnyObject? {
        return attributes[attribute]
    }
}


// MARK: KeychainMatchable

// Indicates that items in the IOS keychain of securityClass can matched with keychainMatchPropertyValues()
public protocol KeychainMatchable {
    /**
    Returns the properties to pass to SecItemCopyMatching() to match IOS keychain items with
    :returns: a dictionary of IOS Keychain values (See Apple Documentation)
    */
    func keychainMatchPropertyValues() -> [ String: AnyObject ]
    var securityClass: SecurityClass { get }
}



// MARK: KeychainFindable

// Marks that the item provides a findInKeychain() method that returns matching keychain items
public protocol KeychainFindable {
    typealias QueryType : KeychainMatchable
    typealias ResultType : KeychainItem
    static func findInKeychain(matchingProperties: QueryType) throws -> ResultType?
}

public protocol InjectKeychainFind : KeychainFindable {

}

extension KeychainFindable where Self : KeychainFindable, Self : InjectKeychainFind {
    public static func findInKeychain(matchingProperties: QueryType) throws -> ResultType?  {
        if let keychainItem = try Keychain.fetchMatchingItem(thatMatchesProperties: matchingProperties) {
            return keychainItem as? ResultType
        }
        return nil
   }
}

//extension KeychainPrivateKey {
//    public static func findInKeychain(matchingProperties: KeychainKeyProperties) throws -> KeychainPrivateKey? {
//        return try Keychain.fetchMatchingItem(thatMatchesProperties: matchingProperties) as? KeychainPrivateKey
//    }
//}
//
//extension KeychainPublicKey {
//    public static func findInKeychain(matchingProperties: KeychainKeyProperties) throws -> KeychainPublicKey? {
//        return try Keychain.fetchMatchingItem(thatMatchesProperties: matchingProperties) as? KeychainPublicKey
//    }
//}


// MARK: KeychainMatching

public protocol KeychainMatching {
    func keychainMatchPropertyValues() -> KeychainProperties
}


extension KeychainItem  {
    public func keychainMatchPropertyValues() -> KeychainProperties {
        return KeychainProperties(keychainItem: self)
    }
}

// MARK: KeychainAddable


// Indicates that the item can be added to the IOS keychain
public protocol KeychainAddable {
    typealias KeychainClassType : KeychainItem, KeychainFindable
    /**
    Adds the item to the IOS keychain
    :returns: an instance of KeychainClassType
    */
    func addToKeychain() throws -> KeychainClassType?
}

public func addItemToKeychain<A:KeychainAddable,F:KeychainFindable where
    A.KeychainClassType == F.ResultType, A: SecItemAddable, A == F.QueryType
    > (a: A) throws -> F.ResultType? {
        try a.secItemAdd()
        return try F.findInKeychain(a as F.QueryType)
}
//where Self : KeychainAddable, Self : SecItemAddable

extension DetachedPrivateKey : KeychainAddable  {
    public func addToKeychain() throws -> KeychainPrivateKey? {
        try self.secItemAdd()
        return try KeychainPrivateKey.findInKeychain(self)
    }
}
//where Self : KeychainAddable, Self : SecItemAddable
extension DetachedPublicKey : KeychainAddable  {
    public func addToKeychain() throws -> KeychainPublicKey? {
        try self.secItemAdd()
        return try KeychainPublicKey.findInKeychain(self)
    }
}


//extension KeychainAddable where Self : KeychainAddable, Self : SecItemAddable {
//    public func addToKeychain<T>() throws -> T? {
//        return addToKeychain(self)
//    }
//}


// MARK: SecItemAddable
public protocol SecItemAddable {
    func secItemAdd() throws -> AnyObject?
}


extension SecItemAddable where Self : SecItemAddable, Self : KeychainMatchable {
    public func secItemAdd() throws -> AnyObject? {
        var item : KeyChainPropertiesData = [ : ]
        item[String(kSecClass)] = SecurityClass.kSecClass(securityClass)
        item += keychainMatchPropertyValues()
        let itemRef: AnyObject? = try SecurityWrapper.secItemAdd(item)
        return itemRef
    }
}


// MARK: KeychainItemClass
public protocol KeychainItemClass  {
    var securityClass: SecurityClass { get }
}


// -MARK: KeychainCommonClassProperties
/**
Properties for Keychain Items of class kSecClassKey
*/
public protocol KeychainCommonClassProperties : KeyChainAttributeStorage {
    var itemAccessGroup: String? { get}
    var itemLabel: String? { get }
}

extension KeychainCommonClassProperties where Self : KeychainCommonClassProperties {
    public var itemLabel: String? {
        get { return attributes[String(kSecAttrLabel)] as? String }
    }
    public var itemAccessGroup: String? {
        get { return attributes[String(kSecAttrAccessGroup)] as? String }
    }
}

// MARK: KeychainItemMetaData
public protocol KeychainItemMetaData : KeyChainAttributeStorage {
    var itemCreationDate: NSDate? { get }
    var itemModificationDate: NSDate? { get }
}

extension KeychainItemMetaData where Self : KeychainItemMetaData {
    public var itemCreationDate: NSDate? {
        get { return attributes[String(kSecAttrCreationDate)] as? NSDate }
    }

    public var itemModificationDate: NSDate? {
        get { return attributes[String(kSecAttrModificationDate)] as? NSDate }
    }
}

// MARK: KeychainKeyClassProperties
/**
Properties for Keychain Items of class kSecClassKey
*/
public protocol KeychainKeyClassProperties {
    var keySize: Int { get }
    var keyPermanent: Bool { get }
    var keyClass: KeyClass { get }
    var keyAppTag: String? { get }
}


/**
Injects IOS Keychain kSecClassKey properties into conforming items
*/
extension KeychainKeyClassProperties where Self : KeychainKeyClassProperties, Self : KeyChainAttributeStorage {
    public var keyAppTag: String? {
        get { return attributes[String(kSecAttrApplicationTag)] as? String }
    }

    public var keyAppLabel: String? {
        get {
            if let data = attributes[String(kSecAttrApplicationLabel)] as? NSData {
                return NSString(data: data, encoding: NSUTF8StringEncoding) as? String
            } else {
                return nil
            }
        }
    }

    public var keyClass: KeyClass {
        get {
            return KeyClass.keyClass(attributes[String(kSecAttrKeyClass)])
        }
    }

    // There is a bug in the Key Chain. You send KeyType as a String (kSecAttrKeyTypeRSA), but what is returned is an NSNumber
    public var keyType:  KeyType? {
        get {
            if let intValue = attributes[String(kSecAttrKeyType)] as? Int {
                switch intValue {
                case 42: return KeyType.RSA
                default : return nil
                }
            } else if let stringValue = attributes[String(kSecAttrKeyType)] as? String {
                return KeyType.init(rawValue: stringValue)
            }
            return nil
        }
    }

    public var keySize: Int {
        get {
            return (attributes[String(kSecAttrKeySizeInBits)] as? NSNumber)!.integerValue
        }
    }

    public var keyPermanent: Bool {
        get {
            return (attributes[String(kSecAttrIsPermanent)] as? NSNumber)?.boolValue ?? false
        }
    }
}

