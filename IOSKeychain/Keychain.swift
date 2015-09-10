//
//  Keychain.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 18/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

public typealias ItemAttributes    = [ String : AnyObject]
public typealias ItemReference     = AnyObject
public typealias KeychainQueryData = [ String : AnyObject]
public typealias KeychainItemData  = [ String : AnyObject]

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
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(dictionary, UnsafeMutablePointer($0)) }
            )
        if status == .OK, let returnValue = result as? T {
            return (status, returnValue)
        }
        return (status, nil)
    }

    public class func secItemCopyMatchingItems(query: KeychainQueryData) -> (KeychainStatus, [ItemAttributes]) {
        var attributes = NSMutableDictionary()
        attributes[String(kSecMatchLimit)]       = kSecMatchLimitAll
        attributes.addEntriesFromDictionary(query)

        var result: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(attributes, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [ItemAttributes] {
            return (status, items)
        }
        return (status, [])
    }


    public class func secItemAdd(attributes: KeychainItemData) -> (KeychainStatus, AnyObject?) {
        var persistedRef: AnyObject?



        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&persistedRef) { SecItemAdd(attributes, UnsafeMutablePointer($0)) }
        )

        if status == .OK {
            println(persistedRef)
            if let data = persistedRef as? NSData {
                println(data)
            }
        }


        return (.OK,[])
//        println(status)
//        println(result)
//        if status == .OK {
//            return (status, nil)
//        }
//        return (status, [])
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

    public class func secPKCS12Import(pkcs12Data: NSData, options: KeychainQueryData) -> (KeychainStatus, [ItemAttributes]) {
        var result: NSArray?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecPKCS12Import(pkcs12Data, options, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [ItemAttributes]
        {
            return (status, items)
        }
        return (status, [])
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

    public class func findKeyPair(specifier: KeyPairSpecification) -> KeyPair? {
        let (privStatus, privateKeyItem) = fetchMatchingItem(itemSpecifier: specifier.privateKeySpecifier())
        let (pubStatus, publicKeyItem)  = fetchMatchingItem(itemSpecifier: specifier.publicKeySpecifier())

        if (privateKeyItem != nil) && (publicKeyItem != nil) {
            let keyPair = KeyPair(publicKey: publicKeyItem as! PublicKey, privateKey: privateKeyItem as! PrivateKey)
            return keyPair
        } else {
            return nil
        }
    }

    public class func generateKeyPair(specification: KeyPairSpecification) -> (KeychainStatus, KeyPair?) {

        let (result, publicKeyRef, privateKeyRef) = SecurityWrapper.secKeyGeneratePair(specification.keychainQuery())

        if result == .OK {
            return (result, findKeyPair(specification))
        } else {
            return (result, nil)
        }
    }



    public class func addKeyPair(key: KeyPairImportSpecification) -> (KeychainStatus, KeyPair?) {

        var item : KeychainQueryData = [ : ]

        item[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)

        item += key.keychainQuery()

        let (result, itemRefs: AnyObject?) = SecurityWrapper.secItemAdd(item)

        if result == .OK {
            return (result, findKeyPair(key))
        } else {
            return (result, nil)
        }
    }

    public class func addIdentity(identity: IdentityImportSpecifier) -> (KeychainStatus, Identity?) {
        var item : KeychainQueryData = [ : ]
        item[String(kSecReturnPersistentRef)] = NSNumber(bool: true);

        item += identity.keychainQuery()

        //There seems to be a bug in the keychain that causes the SecItemAdd for Identities to fail silently when kSecClass is specified :S
        item.removeValueForKey(String(kSecClass))

        let (result, itemRefs: AnyObject?) = SecurityWrapper.secItemAdd(item)

        return (.OK, nil)

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

    public class func importP12Identity(identity: P12Identity) -> IdentityReference? {
        var options : KeychainQueryData = [ : ]

        options[kSecImportExportPassphrase.takeRetainedValue() as String] = identity.importPassphrase

        let (result, itemRefs) = SecurityWrapper.secPKCS12Import(identity.p12EncodedIdentityData, options: options)
        if count(itemRefs) == 1 {
            let item = itemRefs[0]
            let identityRef : SecIdentityRef = itemRefs[0][kSecImportItemIdentity.takeRetainedValue() as String] as! SecIdentityRef
            return IdentityReference(reference: identityRef)
        }
        return nil
    }

    public class func deleteAllItemsOfClass(securityClass: SecurityClass) -> Int {
        return 0
    }
}