//
//  Keychain.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 18/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

public typealias ItemAttributes     = [ String : AnyObject]
public typealias KeychainQueryData  = [ String : AnyObject]

func += <KeyType, ValueType> (inout left: Dictionary<KeyType, ValueType>, right: Dictionary<KeyType, ValueType>) {
    for (k, v) in right {
        left.updateValue(v, forKey: k)
    }
}

public class SecurityWrapper {
    public class func secItemCopyMatchingItem<T>(query: KeychainQueryData) -> (KeychainStatus, T?) {
        var dictionary = NSMutableDictionary()
        dictionary[String(kSecMatchLimit)]       = kSecMatchLimitOne
        dictionary.addEntriesFromDictionary(query)


        var result: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
            )
        if status == .OK, let returnValue = result as? T {
            return (status, returnValue)
        }
        return (status, nil)
    }

    public class func secItemCopyMatchingItems(query: KeychainQueryData) -> (KeychainStatus, [ItemAttributes]) {
        var dictionary = NSMutableDictionary()
        dictionary[String(kSecMatchLimit)]       = kSecMatchLimitAll
        dictionary.addEntriesFromDictionary(query)

        var result: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(query, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [ItemAttributes] {
            return (status, items)
        }
        return (status, [])
    }

    public class func secItemDelete(query: KeychainQueryData) -> KeychainStatus {
        var dictionary = NSMutableDictionary()
        dictionary.addEntriesFromDictionary(query)

        let status = KeychainStatus.statusFromOSStatus(SecItemDelete(dictionary))
        return status
    }

    public class func secKeyGeneratePair(query: KeychainQueryData) -> (KeychainStatus, SecKey?, SecKey?) {
        var publicKeyRef  : Unmanaged<SecKey>?
        var privateKeyRef : Unmanaged<SecKey>?

        var dictionary = NSMutableDictionary()
        dictionary.addEntriesFromDictionary(query)

        let status = KeychainStatus.statusFromOSStatus(
            SecKeyGeneratePair(query, &publicKeyRef, &privateKeyRef))
        if status == .OK {
            return (status, publicKeyRef?.takeRetainedValue(), privateKeyRef?.takeRetainedValue())
        } else {
            return (status, nil, nil)
        }
    }
}

public class Keychain {
    public class func keyChainItems(securityClass: SecurityClass) -> (KeychainStatus, [KeychainItem]) {
        var query : KeychainQueryData = [ : ]
        query[String(kSecClass)]               = SecurityClass.kSecClass(securityClass)
        query[String(kSecReturnData)]          = kCFBooleanTrue
        query[String(kSecReturnAttributes)]    = kCFBooleanTrue
        query[String(kSecReturnRef)]           = kCFBooleanTrue
        query[String(kSecReturnPersistentRef)] = kCFBooleanTrue
        query[String(kSecMatchLimit)]          = kSecMatchLimitAll

        let result   : KeychainStatus
        let itemDicts: [ItemAttributes]

        (result, itemDicts) = SecurityWrapper.secItemCopyMatchingItems(query)

        var items : [KeychainItem] = []

        for itemDict in itemDicts {
            if let item = makeKeyChainItem(securityClass, keychainItemAttributes: itemDict) {
                items.append(item)
            }
        }
        if result == .OK || result == .ItemNotFoundError {
            return (.OK, items)
        } else {
            return (result, items)
        }
    }

    public class func fetchMatchingItem(itemSpecifier specifier: KeychainQuery) -> (KeychainStatus, KeychainItem?) {
        var query : KeychainQueryData = [ : ]

        query[String(kSecClass)]            = SecurityClass.kSecClass(specifier.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanFalse
        query[String(kSecReturnRef)]        = kCFBooleanTrue
        query[String(kSecReturnAttributes)] = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne

        query += specifier.keychainQuery()

        let (result, itemDict: ItemAttributes?) = SecurityWrapper.secItemCopyMatchingItem(query)

        if result == .OK {
            return (.OK, makeKeyChainItem(specifier.securityClass, keychainItemAttributes:  itemDict!))
        }

        return (result, nil)
    }

    public class func deleteKeyChainItem(itemSpecifier specifier: KeychainQuery) -> KeychainStatus {
        return SecurityWrapper.secItemDelete(specifier.keychainQuery())
    }

    class func makeKeyChainItem(securityClass: SecurityClass, keychainItemAttributes attributes: ItemAttributes) -> KeychainItem? {
        return KeychainItem.itemFromAttributes(securityClass, keychainAttributes: attributes)
    }

    public class func findKeyPair(specifier: KeySpecifier) -> KeyPair? {
        return nil;
    }

    public class func generateKeyPair(specification: KeyPairSpecification) -> (KeychainStatus, KeyPair?) {

        let (result, publicKeyRef, privateKeyRef) = SecurityWrapper.secKeyGeneratePair(specification.keychainQuery())

        if result == .OK {
            let (privStatus, privateKeyItem) = fetchMatchingItem(itemSpecifier: specification.privateKeySpecifier())
            let (pubStatus, publicKeyItem)  = fetchMatchingItem(itemSpecifier: specification.publicKeySpecifier())

            if (privateKeyItem != nil) && (publicKeyItem != nil) {
                let keyPair = KeyPair(publicKey: publicKeyItem as! PublicKey, privateKey: privateKeyItem as! PrivateKey)
                return (result, keyPair)
            } else {
                // Not permanent keys can only be constructed with the key refs
                let keyPair = KeyPair(specification: specification, publicKeyRef: publicKeyRef!, privateKeyRef: privateKeyRef!)
                return (result, keyPair)
            }
        } else {
            return (result, nil)
        }
    }

    public class func keyData(key: KeychainKey) -> (KeychainStatus, NSData?) {
        var keyRef: Unmanaged<AnyObject>?

        var query : KeychainQueryData = [ : ]

        let specifier = key.specifier()
        query[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne
        query += specifier.keychainQuery()

        let (result, itemDict: NSData?) = SecurityWrapper.secItemCopyMatchingItem(query)

        if result == .OK {
            return (.OK, itemDict)
        }

        return (result, nil)
    }

    public class func deleteAllItemsOfClass(securityClass: SecurityClass) -> Int {
        return 0
    }
}