//
//  OpenSSLSupport.h
//  Expend
//
//  Created by Rudolph van Graan on 23/06/2014.
//  Copyright (c) 2014 Curoo Limited. All rights reserved.
//


#import <Foundation/Foundation.h>

typedef enum {
    kExCryptoKeyTypeUnknown,
    kExCryptoKeyTypeRSA,
    kExCryptoKeyTypeDSA
} ExCryptoKeyType;

@class OpenSSLKeyPair;
@class OpenSSLRSAKeyPair;
@class OpenSSLIdentity;
@class OpenSSLCertificate;
@class OpenSSLCertificateSigningRequest;

@interface OpenSSL : NSObject
+ (nullable NSData *)generateCSRWithPrivateKeyData:(nonnull NSData *)privateKeyData
                                           csrData:(nonnull NSDictionary *)csrData
                                             error:( NSError* __nullable  * __nullable)error;

+ (nullable OpenSSLKeyPair *)keyPairFromPEMData:(nonnull NSData *)pemData
                          encryptedWithPassword:(nonnull NSString *)passphrase
                                          error:( NSError* __nullable  * __nullable)error;

+ (nullable OpenSSLIdentity *)pkcs12IdentityWithPrivateKeyData:(nonnull NSData *)privateKeyData
                                               certificateData:(nonnull NSData *)certificateData
                                       protectedWithPassphrase:(nonnull NSString *)passphrase
                                                         error:( NSError* __nullable  * __nullable)error;

@end
