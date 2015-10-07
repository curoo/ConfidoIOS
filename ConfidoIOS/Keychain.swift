//
//  Keychain.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 18/08/2015.
//
//

import Foundation

public typealias SecItemAttributes    = [ String : AnyObject]
public typealias ItemReference     = AnyObject
public typealias KeyChainPropertiesData = [ String : AnyObject]
public typealias KeychainItemData  = [ String : AnyObject]

func += <KeyType, ValueType> (inout left: Dictionary<KeyType, ValueType>, right: Dictionary<KeyType, ValueType>) {
    for (k, v) in right {
        left.updateValue(v, forKey: k)
    }
}
public enum KeychainError : ErrorType, CustomStringConvertible {
    case
    NoSecIdentityReference,
    NoSecCertificateReference,
    NoSecKeyReference,
    UnimplementedSecurityClass,
    UnimplementedKeyType(reason: String?),
    MismatchedResultType(returnedType: AnyClass, declaredType: Any),
    InvalidCertificateData,
    TrustError(trustResult: TrustResult, reason: String?),
    DataExceedsBlockSize(size: Int),
    InitialVectorMismatch(size: Int),
    CryptoOperationFailed(status: Int32)

    public var description : String {
        switch self {
        case NoSecIdentityReference: return "NoSecIdentityReference"
        case NoSecCertificateReference: return "NoSecCertificateReference"
        case NoSecKeyReference: return "NoSecKeyReference"
        case UnimplementedSecurityClass: return "UnimplementedSecurityClass"
        case UnimplementedKeyType(let reason): return "UnimplementedKeyType \(reason)"
        case MismatchedResultType(let returnedType, let declaredType) : return "MismatchedResultType (returned \(returnedType)) declared \(declaredType)"
        case InvalidCertificateData: return "InvalidCertificateData"
        case TrustError(_, let reason) : return "TrustError \(reason)"
        case DataExceedsBlockSize(let size) : return "Data exceeds cipher block size of \(size)"
        case InitialVectorMismatch(let size) : return "Size of Initial Vector does not match block size of cipher (\(size))"
        case .CryptoOperationFailed(let status): return "Common Crypto Operation Failed (\(status))"
        }
    }
}

/**
Wraps the raw secXYZ APIs
*/
public class SecurityWrapper {
    /**
    A typical query consists of:

    * a kSecClass key, whose value is a constant from the Class
    Constants section that specifies the class of item(s) to be searched
    * one or more keys from the "Attribute Key Constants" section, whose value
    is the attribute data to be matched
    * one or more keys from the "Search Constants" section, whose value is
    used to further refine the search
    * a key from the "Return Type Key Constants" section, specifying the type of
    results desired

    Result types are specified as follows:

    * To obtain the data of a matching item (CFDataRef), specify
    kSecReturnData with a value of kCFBooleanTrue.
    * To obtain the attributes of a matching item (CFDictionaryRef), specify
    kSecReturnAttributes with a value of kCFBooleanTrue.
    * To obtain a reference to a matching item (SecKeychainItemRef,
    SecKeyRef, SecCertificateRef, or SecIdentityRef), specify kSecReturnRef
    with a value of kCFBooleanTrue.
    * To obtain a persistent reference to a matching item (CFDataRef),
    specify kSecReturnPersistentRef with a value of kCFBooleanTrue. Note
    that unlike normal references, a persistent reference may be stored
    on disk or passed between processes.
    * If more than one of these result types is specified, the result is
    returned as a CFDictionaryRef containing all the requested data.
    * If a result type is not specified, no results are returned.

    By default, this function returns only the first match found. To obtain
    more than one matching item at a time, specify kSecMatchLimit with a value
    greater than 1. The result will be a CFArrayRef containing up to that
    number of matching items; the items' types are described above.

    To filter a provided list of items down to those matching the query,
    specify a kSecMatchItemList whose value is a CFArray of SecKeychainItemRef,
    SecKeyRef, SecCertificateRef, or SecIdentityRef items. The objects in the
    provided array must be of the same type.

    To convert from a persistent item reference to a normal item reference,
    specify a kSecValuePersistentRef whose value a CFDataRef (the persistent
    reference), and a kSecReturnRef whose value is kCFBooleanTrue.
    */

    public class func secItemCopyMatching<T>(query: KeyChainPropertiesData) throws -> T {
        var result: AnyObject?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
            )
        if status == .OK, let returnValue = result as? T {
            return returnValue
        } else if status == .OK, let returnValue = result {
            throw KeychainError.MismatchedResultType(returnedType: returnValue.dynamicType, declaredType: T.self)
        } else if status == .OK {
            throw KeychainStatus.ItemNotFoundError
        }
        throw status
    }

    public class func secItemAdd(attributes: KeychainItemData) throws -> AnyObject?  {
        var persistedRef: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&persistedRef) { SecItemAdd(attributes, UnsafeMutablePointer($0)) }
        )

        if status == .OK {
            print(persistedRef)
            if let data = persistedRef as? NSData {
                print(data)
            }
        }
        return []
    }

    public class func secItemDelete(query: KeyChainPropertiesData) throws  {
        let dictionary = NSMutableDictionary()
        dictionary.addEntriesFromDictionary(query)

        let status = KeychainStatus.statusFromOSStatus(SecItemDelete(dictionary))
        if status == .OK {
            return
        }
        throw status
    }

    public class func secPKCS12Import(pkcs12Data: NSData, options: KeyChainPropertiesData) throws -> [SecItemAttributes] {
        var result: NSArray?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecPKCS12Import(pkcs12Data, options, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [SecItemAttributes]
        {
            return items
        }
        else if status == .OK {
            return []
        }
        throw status
    }
}

public enum KeychainReturnLimit {
    case One, All
}

public class Keychain {
    public class func keyChainItems(securityClass: SecurityClass) throws -> [KeychainItem] {
        return try fetchItems(matchingDescriptor: KeychainDescriptor(securityClass: securityClass), returning: .All)
    }

    public class func fetchItems(matchingDescriptor attributes: KeychainMatchable, returning: KeychainReturnLimit, returnData: Bool = false, returnRef: Bool = true) throws -> [KeychainItem] {
        var query : KeyChainPropertiesData = [ : ]

        query[String(kSecClass)]            = SecurityClass.kSecClass(attributes.securityClass)
        // kSecReturnAttributes true to ensure we don't get a raw SecKeychainItemRef or NSData back, this function can't handle it
        // This means we should get either a Dictionary or [Dictionary]
        query[String(kSecReturnAttributes)] = kCFBooleanTrue
        query[String(kSecReturnData)]       = returnData ? kCFBooleanTrue : kCFBooleanFalse
        query[String(kSecReturnRef)]        = returnRef ? kCFBooleanTrue : kCFBooleanFalse
        query[String(kSecMatchLimit)]       = returning == .One ? kSecMatchLimitOne : kSecMatchLimitAll
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query += attributes.keychainMatchPropertyValues()

        do {
            var keychainItemDicts : [SecItemAttributes] = []

            let itemDictOrDicts : NSObject = try SecurityWrapper.secItemCopyMatching(query)
            if let itemDicts = itemDictOrDicts as? [SecItemAttributes] {
                keychainItemDicts = itemDicts
            } else if let itemDict = itemDictOrDicts as? SecItemAttributes {
                keychainItemDicts.append(itemDict)
            }
            return try keychainItemDicts.flatMap { try makeKeyChainItem(attributes.securityClass, keychainItemAttributes: $0) }
        }
        catch KeychainStatus.ItemNotFoundError {
            return []
        }
    }

    public class func fetchItem(matchingDescriptor attributes: KeychainMatchable, returnData: Bool = false, returnRef: Bool = true) throws -> KeychainItem {
        let results = try self.fetchItems(matchingDescriptor: attributes, returning: .One, returnData: returnData, returnRef: returnRef)
        if results.count == 1 { return results[0] }
        throw KeychainStatus.ItemNotFoundError
    }

    public class func deleteKeyChainItem(itemDescriptor descriptor: KeychainMatchable) throws  {
        try SecurityWrapper.secItemDelete(descriptor.keychainMatchPropertyValues())
    }

    class func makeKeyChainItem(securityClass: SecurityClass, keychainItemAttributes attributes: SecItemAttributes) throws -> KeychainItem? {
        return try KeychainItem.itemFromAttributes(securityClass, SecItemAttributes: attributes)
    }



//    public class func addIdentity(identity: IdentityImportSpecifier) throws -> (KeychainStatus, Identity?) {
//        var item : KeyChainPropertiesData = [ : ]
//        item[String(kSecReturnPersistentRef)] = NSNumber(bool: true);
//
//        item += identity.keychainMatchPropertyValues()
//
//        //There seems to be a bug in the keychain that causes the SecItemAdd for Identities to fail silently when kSecClass is specified :S
//        item.removeValueForKey(String(kSecClass))
//
//        let itemRefs: AnyObject? = try SecurityWrapper.secItemAdd(item)
//
//    }

    public class func keyData(key: KeychainPublicKey) throws -> NSData {
        var query : KeyChainPropertiesData = [ : ]

        let descriptor = key.keychainMatchPropertyValues()
        query[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne
        query += descriptor.keychainMatchPropertyValues()

        let keyData: NSData = try SecurityWrapper.secItemCopyMatching(query)
        return keyData

    }

/**
    Attempts to delete all items of a specific security class
    :param: securityClass the class of item to delete
    :returns: (successCount:Int, failureCount:Int)
*/
    public class func deleteAllItemsOfClass(securityClass: SecurityClass) -> (Int,Int) {
        do {
            let items = try Keychain.keyChainItems(securityClass)

            var successCount = 0
            var failCount    = 0
            for item in items {
                do {
                    try Keychain.deleteKeyChainItem(itemDescriptor: item.keychainMatchPropertyValues())
                    successCount++
                } catch {
                    failCount++
                }
            }
            return (successCount, failCount)
        } catch {
            return (0,0)
        }
    }
}





