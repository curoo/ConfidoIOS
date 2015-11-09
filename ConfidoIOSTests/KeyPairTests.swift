//
//  KeyPairTests.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//

import UIKit
import XCTest
import ConfidoIOS

class KeyPairTests: BaseTests {

    func testGenerateNamedRSAKeyPair() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.WhenUnlockedThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: .RSA, keySize: 1024, keyLabel: "AAA", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
            var keyPair : KeychainKeyPair!
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)


            let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchItem(matchingDescriptor: keyDescriptor)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair.privateKey.keyType, KeyType.RSA)
            XCTAssertEqual(keyPair.publicKey.keyType, KeyType.RSA)


            XCTAssertEqual(keyPair.privateKey.keySize, 1024)
            XCTAssertEqual(keyPair.publicKey.keySize, 1024)

            XCTAssertNotNil(keyPair.privateKey.itemLabel)
            XCTAssertEqual(keyPair.privateKey.itemLabel!, "AAA")

            XCTAssertNotNil(keyPair.privateKey.keyAppTag)
            XCTAssertEqual(keyPair.privateKey.keyAppTag!, "BBB")

            XCTAssertNil(keyPair.privateKey.keyAppLabelString)
            XCTAssertNotNil(keyPair.publicKey.keyAppLabelString)
            XCTAssertEqual(keyPair.publicKey.keyAppLabelString!, "CCC")

            XCTAssertEqual(keyPair.publicKey.itemAccessGroup, "")
            XCTAssertEqual(keyPair.publicKey.itemAccessible, Accessible.WhenUnlockedThisDeviceOnly)

            let publicKeyData = keyPair.publicKey.keyData
            XCTAssertNotNil(publicKeyData)

            XCTAssertEqual(publicKeyData!.length,140)

            let signature = try keyPair.privateKey.sign(Buffer(bytes:[1,2,3,4,5,6,7,8]))
            print(signature)

            var verified = try keyPair.publicKey.verify(Buffer(bytes:[1,2,3,4,5,6,7,8]), signature: signature)
            XCTAssertTrue(verified)

            verified = try keyPair.publicKey.verify(Buffer(bytes:[1,2,3,4,5,6,7,8,9]), signature: signature)
            XCTAssertFalse(verified)

            let cipherTextUnderPublicKey = try keyPair.publicKey.encrypt(Buffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
            print("Cipher under public key: \(cipherTextUnderPublicKey)")

            let decryptedText = try keyPair.privateKey.decrypt(cipherTextUnderPublicKey, padding: SecPadding.OAEP)
            XCTAssertEqual([1,2,3,4], decryptedText.values)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testGenerateNamedECKeyPairSignVerify() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.WhenUnlockedThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: KeyType.ElypticCurve, keySize: 256, keyLabel: "AAA", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
            var keyPair : KeychainKeyPair!
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)


            let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchItem(matchingDescriptor: keyDescriptor)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair.privateKey.keyType, KeyType.ElypticCurve)
            XCTAssertEqual(keyPair.publicKey.keyType, KeyType.ElypticCurve)


            XCTAssertEqual(keyPair.privateKey.keySize, 256)
            XCTAssertEqual(keyPair.publicKey.keySize, 256)


            let publicKeyData = keyPair.publicKey.keyData
            XCTAssertNotNil(publicKeyData)

            XCTAssertEqual(publicKeyData!.length,65)

            let signature = try keyPair.privateKey.sign(Buffer(bytes:[1,2,3,4,5,6,7,8]))
            print("Signature: \(signature.hexString)")

            var verified = try keyPair.publicKey.verify(Buffer(bytes:[1,2,3,4,5,6,7,8]), signature: signature)
            XCTAssertTrue(verified)

            verified = try keyPair.publicKey.verify(Buffer(bytes:[1,2,3,4,5,6,7,8,9]), signature: signature)
            XCTAssertFalse(verified)


        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }


    func testGenerateNamedECKeyPairEncryptDecrypt() {
        // This test fails because it seems that Apple has not implemented encrypting/decrypting (only signing) for EC keys.
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.WhenUnlockedThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: KeyType.ElypticCurve, keySize: 256, keyLabel: "AAA", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
            var keyPair : KeychainKeyPair!
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)


            let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchItem(matchingDescriptor: keyDescriptor)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair.privateKey.keyType, KeyType.ElypticCurve)
            XCTAssertEqual(keyPair.publicKey.keyType, KeyType.ElypticCurve)


            let publicKeyData = keyPair.publicKey.keyData
            XCTAssertNotNil(publicKeyData)

            XCTAssertEqual(publicKeyData!.length,65)


            let cipherTextUnderPublicKey = try keyPair.publicKey.encrypt(Buffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
            print("Cipher under public key: \(cipherTextUnderPublicKey)")

            let decryptedText = try keyPair.privateKey.decrypt(cipherTextUnderPublicKey, padding: SecPadding.OAEP)
            XCTAssertEqual([1,2,3,4], decryptedText.values)
            
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }



    func testGenerateKeyPairDifferentLabels() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)
            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: .WhenUnlockedThisDeviceOnly,
                keyLabel: "KPriv", privateKeyAppTag: nil, privateKeyAccessControl: nil,
                publicKeyAppLabel: "KPub", publicKeyAppTag: nil, publicKeyAccessControl: nil,
                keyType: .RSA, keySize: 1024)

            var keyPair : KeychainKeyPair!
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)


            let privKeyDescriptor = KeychainKeyDescriptor(keyClass: KeyClass.PrivateKey, keyLabel: "KPriv")
            var privKeyItem: KeychainItem?
            privKeyItem = try Keychain.fetchItem(matchingDescriptor: privKeyDescriptor)
            XCTAssertNotNil(privKeyItem)

            XCTAssert(privKeyItem is KeychainPrivateKey)

            let pubKeyDescriptor = KeychainKeyDescriptor(keyClass: KeyClass.PublicKey, keyLabel: "KPriv", keyAppLabel: "KPub")
            var pubKeyItem: KeychainItem?
            pubKeyItem = try Keychain.fetchItem(matchingDescriptor: pubKeyDescriptor)
            XCTAssertNotNil(pubKeyItem)

            XCTAssert(pubKeyItem is KeychainPublicKey)
            let publicKey  =  pubKeyItem as! KeychainPublicKey
            let privateKey = privKeyItem as! KeychainPrivateKey

            let publicKeyData = publicKey.keyData
            XCTAssertNotNil(publicKeyData)

            XCTAssertEqual(publicKeyData!.length,140)

            let signature = try privateKey.sign(Buffer(bytes:[1,2,3,4,5,6,7,8]))
            print(signature)

            var verified = try publicKey.verify(Buffer(bytes:[1,2,3,4,5,6,7,8]), signature: signature)
            XCTAssertTrue(verified)

            verified = try publicKey.verify(Buffer(bytes:[1,2,3,4,5,6,7,8,9]), signature: signature)
            XCTAssertFalse(verified)

            let cipherTextUnderPublicKey = try publicKey.encrypt(Buffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
            print("Cipher under public key: \(cipherTextUnderPublicKey)")

            let decryptedText = try privateKey.decrypt(cipherTextUnderPublicKey, padding: SecPadding.OAEP)
            XCTAssertEqual([1,2,3,4], decryptedText.values)
            

            
        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
        
        
    }

    func testGenerateNamedKeyPairNoKeyLabel() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(
                accessible: Accessible.AlwaysThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: .RSA, keySize: 1024, keyLabel: "AAA")
            var keyPair : KeychainKeyPair?
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)

            let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchItem(matchingDescriptor: keyDescriptor)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair!.privateKey.keyType, KeyType.RSA)
            XCTAssertEqual(keyPair!.publicKey.keyType, KeyType.RSA)


            XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
            XCTAssertEqual(keyPair!.publicKey.keySize, 1024)

            XCTAssertNotNil(keyPair!.privateKey.itemLabel)
            XCTAssertEqual(keyPair!.privateKey.itemLabel!, "AAA")

            XCTAssertNotNil(keyPair!.privateKey.keyAppTag)
            XCTAssertEqual(keyPair!.privateKey.keyAppTag!, "")

            XCTAssertNotNil(keyPair!.privateKey.keyAppLabelData)
            //The keyAppLabel is equal to the hash of the public key by default

            let publicKeyData = keyPair!.publicKey.keyData
            XCTAssertNotNil(publicKeyData)


            XCTAssertEqual(publicKeyData!.length,140)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
        
        
    }

    
    func testGenerateUnnamedKeyPair() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = TemporaryKeychainKeyPairDescriptor(keyType: .RSA, keySize: 1024)
            let keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items =  try Keychain.keyChainItems(.Key)
            // Temporary keys are not stored in the keychain
            XCTAssertEqual(items.count,0)

            XCTAssertEqual(keyPair.privateKey.keySize, 1024)
            XCTAssertEqual(keyPair.publicKey.keySize, 1024)


            // There is no way to extract the data of a key for non-permanent keys
            let publicKeyData = keyPair.publicKey.keyData
            XCTAssertNil(publicKeyData)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testDuplicateKeyPairMatching() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            var keypairDescriptor = PermanentKeychainKeyPairDescriptor(
                accessible: Accessible.AlwaysThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: .RSA, keySize: 1024, keyLabel: "A1", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
            var keyPair : KeychainKeyPair? = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)


            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)

            // Test that labels make the keypair unique
            do {
                keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
                XCTFail("Expected DuplicateItemError")
            } catch KeychainStatus.DuplicateItemError {
                // keySize, keyLabel, keyAppTag, keyAppLabel all the same --> DuplicateItemError
            }

            // different keySize
            keypairDescriptor = PermanentKeychainKeyPairDescriptor(
                accessible: Accessible.AlwaysThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: .RSA, keySize: 2048, keyLabel: "A1", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)
        } catch let error {
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testExportCSR (){
        do {
            clearKeychainItems(.Key)
            let items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(
                accessible: Accessible.AlwaysThisDeviceOnly,
                privateKeyAccessControl: nil, publicKeyAccessControl: nil,
                keyType: .RSA, keySize: 1024, keyLabel: "KeyPair for CSR")
            let keyPair : KeychainKeyPair! = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            let attributes = [
                "UID" : "Test Device",
                "CN" : "Expend Device ABCD" ]

            let csr = try OpenSSL.generateCSRWithPrivateKeyData(keyPair.privateKey.keyData(), csrData: attributes)
            XCTAssertNotNil(csr)
            let csrString : NSString! = NSString(data: csr, encoding: NSUTF8StringEncoding)
            XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
            XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
            print("CSR:")
            print(csrString)
        } catch let error{
            XCTFail("Unexpected Exception \(error)")
        }
        
    }

    func testPublicKeyFromDERFile() {
        do {
            clearKeychainItems(.Key)
            let publicKeyData = try contentsOfBundleResource("public-key", ofType: "der")
            let publicKey = try KeychainPublicKey.importRSAPublicKey(derEncodedData: publicKeyData, keyLabel: "build-key")
            let cipherTextUnderPublicKey = try publicKey.encrypt(Buffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
            print("Cipher under public key: \(cipherTextUnderPublicKey)")

        } catch let error{
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testTwoPublicKeysDifferentAppTagsSameLabel() {
        // In the keychain, keyAppTag is unique, so no two items can share it.
        // itemLabel is not unique, so two items can have the same label
        var items = try! Keychain.keyChainItems(SecurityClass.Key)

        clearKeychainItems(.Key)
        let publicKeyData = try! contentsOfBundleResource("public-key", ofType: "der")
        let publicKey = try! KeychainPublicKey.importRSAPublicKey(derEncodedData: publicKeyData, keyLabel: "build-key", keyAppTag: "build")

        items = try! Keychain.keyChainItems(SecurityClass.Key)
        XCTAssertEqual(items.count,1)

        let cipherTextUnderPublicKey = try! publicKey.encrypt(Buffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
        print("Cipher under public key: \(cipherTextUnderPublicKey)")

        let publicKeyData2 = try! contentsOfBundleResource("development-build-public-key", ofType: "der")

        let publicKey2 = try! KeychainPublicKey.importRSAPublicKey(derEncodedData: publicKeyData2, keyLabel: "build-key", keyAppTag: "build-1")
        XCTAssertNotNil(publicKey2)
        items = try! Keychain.keyChainItems(SecurityClass.Key)
        XCTAssertEqual(items.count,2)
        let matchingDescriptor = PublicKeyMatchingDescriptor(keyLabel: "build-key", keyAppTag: nil)
        var keys = KeychainPublicKey.existingKeys(matchingDescriptor)
        XCTAssertEqual(keys.count,2)

        try! Keychain.deleteKeyChainItem(itemDescriptor: matchingDescriptor)
        keys = KeychainPublicKey.existingKeys(matchingDescriptor)
        XCTAssertEqual(keys.count,0)

    }



}
