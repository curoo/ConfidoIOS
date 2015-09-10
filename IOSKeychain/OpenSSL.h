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
@class OpenSSLIdentity;
@class OpenSSLCertificate;
@class OpenSSLCertificateSigningRequest;

@interface OpenSSL : NSObject
+ (nullable NSData *)generateCSRWithKeyPair:(nonnull OpenSSLKeyPair *)keyPair
                                    csrData:(nonnull NSDictionary *)csrData
                                      error:( NSError* __nullable  * __nullable)error;

+ (nullable OpenSSLKeyPair *)keyPairFromPEMData:(nonnull NSData *)pemData
                          encryptedWithPassword:(nonnull NSString *)passphrase
                                          error:( NSError* __nullable  * __nullable)error;


+ (nullable OpenSSLIdentity *)pkcs12IdentityWithKeyPair:(nonnull OpenSSLKeyPair *)keyPair
                                            certificate:(nonnull OpenSSLCertificate *)certificate
                                protectedWithPassphrase:(nonnull NSString *)passphrase
                                                  error:( NSError* __nullable  * __nullable)error;

@end
