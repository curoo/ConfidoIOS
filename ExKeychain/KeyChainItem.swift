//
//  KeyChainItem.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 18/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation
import Security



// Update -> Add writers for functions, populate separate dictionary, something calls update

public class KeychainItem: KeychainAttributeBag {
    public private(set) var securityClass: SecurityClass

    public class func itemFromAttributes(securityClass: SecurityClass, keychainAttributes attributes: ItemAttributes) -> KeychainItem? {
        switch securityClass {
        case .Key: return KeychainKey.keychainKeyFromAttributes(keychainAttributes: attributes)
        default: return nil
        }
    }

    init(securityClass: SecurityClass, attributeBag: KeychainAttributeBag? = nil) {
        self.securityClass = securityClass
        super.init(attributeBag: attributeBag)
    }

    init(securityClass: SecurityClass, keychainAttributes attributes: NSDictionary) {
        if let secClass: AnyObject = attributes[String(kSecClass)] {
            self.securityClass = SecurityClass.securityClass(secClass)!
        } else {
            self.securityClass = securityClass
        }
        super.init(keychainAttributes: attributes)
    }

    public func specifierMatchingProperties() -> Set<SecAttr> {
        return kCommonMatchingProperties
    }

    public func specifier() -> KeychainItemSpecifier {
        return KeychainItemSpecifier(keychainItem: self)
    }


}


//public class KeychainInternetPassword : KeychainItem {
//
//    public init(userAccount: String, service: String = ExpendDefaultService) {
//        super.init(securityClass: .GenericPassword)
//        self.userAccount = userAccount
//        self.itemService = service
//    }
//
//    public static let searchProperties = kInternetPasswordSearchProperties
//    public static let itemProperties   = kInternetPasswordProperties
//
//}




//
//}
//
