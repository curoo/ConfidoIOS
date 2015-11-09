//
//  BaseTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 14/09/2015.
//

import Foundation
import XCTest
import ConfidoIOS


enum TestError : ErrorType {
    case UnknownResourceInBundle, ResourceAccessError
}

public class BaseTests: XCTestCase {
    func testsBundle() -> NSBundle {
        return NSBundle(forClass: self.dynamicType)
    }
    func contentsOfBundleResource(resourceName: String, ofType resourceType: String) throws -> NSData {
        if let path = testsBundle().pathForResource(resourceName, ofType: resourceType) {
            if let data = NSData(contentsOfFile: path) {
                return data
            }
            throw TestError.ResourceAccessError
        }
        throw TestError.UnknownResourceInBundle
    }

    func keychainItems(type: SecurityClass) -> [KeychainItem] {
        do {
            return try Keychain.keyChainItems(type)
        } catch {
            return []
        }
    }

    func clearKeychainItems(type: SecurityClass) {
        do {
            let items = try Keychain.keyChainItems(type)

            let n = items.count
            print("Deleting \(n) \(type) items from keychain")
            let (successCount, failureCount) = Keychain.deleteAllItemsOfClass(type)
            XCTAssertEqual(items.count,successCount)
            XCTAssertEqual(failureCount,0)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
        
    }
}
