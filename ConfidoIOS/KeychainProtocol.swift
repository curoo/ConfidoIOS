//
//  KeychainProtocol.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 11/09/2015.
//
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

// This is used to flag specific classes to use the generic findInKeychain() below, otherwise the method needs ot be written by hand
public protocol GenerateKeychainFind : KeychainFindable {
}

extension KeychainFindable where Self : KeychainFindable, Self : GenerateKeychainFind {
    public static func findInKeychain(matchingProperties: QueryType) throws -> ResultType?  {
        let keychainItem = try Keychain.fetchItem(matchingDescriptor: matchingProperties)
        if let result = keychainItem as? ResultType {
            return result
        }
        throw KeychainError.MismatchedResultType(returnedType: keychainItem.dynamicType.self, declaredType: QueryType.self)
   }
}

// MARK: KeychainMatching

public protocol KeychainMatching {
    func keychainMatchPropertyValues() -> KeychainDescriptor
}


extension KeychainItem  {
    public func keychainMatchPropertyValues() -> KeychainDescriptor {
        return KeychainDescriptor(keychainItem: self)
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



//TODO: The two extensions above should be replaced with a generic extension similar to this
//extension KeychainAddable where Self : KeychainAddable, Self : SecItemAddable {
//    public func addToKeychain<T>() throws -> T? {
//        return addToKeychain(self)
//    }
//}


// MARK: SecItemAddable
// Generic Protocol to mark that the item can be added to the IOS Keychain
public protocol SecItemAddable : KeyChainAttributeStorage {
    func secItemAdd() throws -> AnyObject?
}

extension SecItemAddable where Self : SecItemAddable, Self : KeychainMatchable {
    public func secItemAdd() throws -> AnyObject? {
        var item : KeyChainPropertiesData = [ : ]
        item += self.attributes
        item[String(kSecClass)] = SecurityClass.kSecClass(securityClass)
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
    //TODO: rename itemLabel to label
    var itemLabel: String? { get }
    var itemAccessible: Accessible? { get }

    /**
    @constant kSecAttrAccessControl Specifies a dictionary key whose value
    is SecAccessControl instance which contains access control conditions
    for item.
    */
    var itemAccessControl: SecAccessControl? { get }

    /**
    @constant kSecAttrTokenID Specifies a dictionary key whose presence
    indicates that item is backed by external token. Value of this attribute
    is CFStringRef uniquely identifying containing token. When this attribute
    is not present, item is stored in internal keychain database.
    Note that once item is created, this attribute cannot be changed - in other
    words it is not possible to migrate existing items to, from or between tokens.
    Currently the only available value for this attribute is
    kSecAttrTokenIDSecureEnclave, which indicates that item (private key) is
    backed by device's Secure Enclave.
    */
    @available (iOS 9.0, *)
    var itemTokenID: String? { get }
}


extension KeychainCommonClassProperties where Self : KeychainCommonClassProperties {
    public var itemLabel: String? {
        get { return attributes[String(kSecAttrLabel)] as? String }
    }
    public var itemAccessGroup: String? {
        get { return attributes[String(kSecAttrAccessGroup)] as? String }
    }
    public var itemAccessible: Accessible? {
        get {
            let accessible = attributes[String(kSecAttrAccessible)] as? String
            if accessible != nil {
                return Accessible.init(rawValue: accessible!)
            }
            return nil
        }
    }
    public var itemAccessControl: SecAccessControl? {
        get {
            if let valueRef: AnyObject = attributes[String(kSecAttrAccessControl)] {
                if CFGetTypeID(valueRef) == SecAccessControlGetTypeID() {
                    return (valueRef as! SecAccessControl)
                }
            }
            return nil
        }
    }

    public var itemTokenID: String? {
        get {
            if #available(iOS 9.0,*) {
                return attributes[String(kSecAttrTokenID)] as? String
            } else {
                return nil
            }
        }
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

    public var keyAppLabelString: String? {
        get {
            if let data = attributes[String(kSecAttrApplicationLabel)] as? NSData {
                return NSString(data: data, encoding: NSUTF8StringEncoding) as? String
            } else {
                return nil
            }
        }
    }
    public var keyAppLabelData: NSData? {
        get {
            if let data = attributes[String(kSecAttrApplicationLabel)] as? NSData {
                return data
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
                case 73: return KeyType.ElypticCurve
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



// MARK: KeychainCertificateClassProperties
/**
Properties for Keychain Items of class kSecClassCertificate
*/
public protocol KeychainCertificateClassProperties {
    var subjectX509Data: NSData { get }
    var issuerX509Data: NSData { get }
    var serialNumberX509Data: NSData { get }
    var subjectKeyID: AnyObject { get }
    var publicKeyHash: AnyObject { get }
}


/**
Injects IOS Keychain kSecClassCertificate properties into conforming items
*/
extension KeychainCertificateClassProperties where Self : KeychainCertificateClassProperties, Self : KeyChainAttributeStorage {
    public var subjectX509Data: NSData {
        get { return attributes[kSecAttrSubject as String] as! NSData }
    }
    public var issuerX509Data: NSData {
        get { return attributes[kSecAttrIssuer as String] as! NSData }
    }
    public var serialNumberX509Data: NSData {
        get { return attributes[kSecAttrSerialNumber as String] as! NSData }
    }
    public var subjectKeyID: AnyObject {
        get { return attributes[kSecAttrSubjectKeyID as String]! }
    }
    public var publicKeyHash: AnyObject {
        get { return attributes[kSecAttrPublicKeyHash as String]!  }
    }
}


