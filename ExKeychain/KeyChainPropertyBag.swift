//
//  KeyChainPropertyBag.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 20/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation
import Security



/*
Encapsulates the attributes of a keychain item
*/
public class KeychainAttributeBag {
    var attributes : [SecAttr : AnyObject] = [ : ]

    subscript(attribute: SecAttr) -> AnyObject? {
        return attributes[attribute]
    }

    public var itemAccessGroup: String? {
        get { return attributes[.AccessGroup] as? String }
        set { attributes[.AccessGroup] = newValue }
    }

    public var itemLabel: String? {
        set { attributes[.Label] = newValue }
        get { return attributes[.Label] as? String }
    }

    public var itemCreationDate: NSDate? {
        get { return attributes[.CreationDate] as? NSDate }
    }

    public var itemModificationDate: NSDate? {
        get { return attributes[.ModificationDate] as? NSDate }
    }

    init(attributeBag: KeychainAttributeBag? = nil) {
        if attributeBag != nil {
            self.attributes = attributeBag!.attributes
        }

    }

    init(keychainAttributes: NSDictionary) {
        for (key, object) in keychainAttributes {
            if let enumKey = SecAttr.secAttr(key) {
                attributes[enumKey] = object
            }
        }
    }

    init(attributeBag: KeychainAttributeBag) {
        self.attributes = attributeBag.attributes
    }
}



