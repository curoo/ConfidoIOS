//
//  OpenSSLSupport.m
//  Expend
//
//  Created by Rudolph van Graan on 23/06/2014.
//  Copyright (c) 2014 Curoo Limited. All rights reserved.
//


#import <IOSKeychain/IOSKeychain-Swift.h>

#import "OpenSSL.h"
//#import "ExKCCertificate.h"
//#import "ExKCKeyPair.h"
#import <openssl/x509.h>
#import <openssl/pem.h>

#import "pkcs12.h"
#import <openssl/err.h>


ExCryptoKeyType map_EVP_PKEY_Type(EVP_PKEY *aEVPKey);

@implementation OpenSSL {

}

+ (void)initialize {
    [super initialize];
    ERR_load_ERR_strings();
    ERR_load_PEM_strings();
    ERR_load_EVP_strings();
    ERR_load_PKCS7_strings();
    OPENSSL_add_all_algorithms_conf();
}


+ (nullable NSData *)generateCSRWithKeyPair:(nonnull OpenSSLKeyPair *)keyPair
                                    csrData:(nonnull NSDictionary *)csrData
                                      error:( NSError* __nullable  * __nullable)error  {
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    EVP_MD *digest = NULL;
    BIO *bio = NULL;
    BIO *bioStdOut = NULL;
    EVP_PKEY *evpPrivKey  = NULL;
    NSError *localError = nil;
    @try {
        bioStdOut = BIO_new_fd(fileno(stdout), BIO_NOCLOSE);
        evpPrivKey = [self createEVP_PKEYfromData:keyPair.privateKeyData error:&localError];

        if (!evpPrivKey) {
            if (error != NULL) { *error = localError; }
            return nil;
        }

        if ((req = X509_REQ_new()) == NULL) {
            if (error != NULL) { *error = [self internalError:@"X509_REQ_new failed"]; }
            return nil;
        }


//        EVP_PKEY_print_private(bioStdOut, evpPrivKey, 4, NULL);


        name = X509_REQ_get_subject_name(req);
        if (!X509_REQ_set_pubkey(req, evpPrivKey)) {
            if (error != NULL) { *error = [self internalError:@"X509_REQ_set_pubkey failed"]; }
            return nil;
        }

        if (csrData[@"CN"]) {
            NSString *cnString = csrData[@"CN"];
            if (!X509_NAME_add_entry_by_txt(name, "CN",
                                            MBSTRING_ASC, (unsigned char const *) [cnString UTF8String], -1, -1, 0)) {
                if (error != NULL) { *error = [self internalError:[NSString stringWithFormat:@"X509_NAME_add_entry_by_txt failed for CN=%@", csrData[@"CN"]]]; }
                return nil;
            }
        }
        if (csrData[@"UID"]) {
            if (!X509_NAME_add_entry_by_txt(name, "UID",
                                            MBSTRING_ASC, (unsigned char const *) [csrData[@"UID"] UTF8String], -1, -1, 0)) {
                if (error != NULL) { *error = [self internalError:[NSString stringWithFormat:@"X509_NAME_add_entry_by_txt failed for UID=%@", csrData[@"UID"]]]; }
                return nil;
            }

        }
        X509_REQ_set_version(req, 1);
//        X509_REQ_print(bioStdOut, req);
        digest = (EVP_MD *) EVP_sha256();
        if (!X509_REQ_sign(req, evpPrivKey, digest)) {
            ERR_print_errors_fp(stdout);
            if (error != NULL) { *error = [self internalError:@"X509_REQ_sign failed"]; }
            return nil;

        }
//        X509_REQ_print(bioStdOut, req);


        bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_X509_REQ(bio, req)) {
            if (error != NULL) { *error = [self internalError:@"PEM_write_bio_X509_REQ failed"]; }
            return nil;
        }
        NSData *data = [self BIOtoNSData:bio error:&localError];
        if (data == nil) {
            if (error != NULL) { *error = localError; }
            return nil;
        }

        return data;
    }
    @finally {
        BIO_free(bio);
        EVP_PKEY_free(evpPrivKey);
        X509_REQ_free(req);
        BIO_free(bioStdOut);
    }
}

+ (EVP_PKEY *)createEVP_PKEYfromData:(NSData *)privKeyData error:( NSError* __nullable  * __nullable)error{
    EVP_PKEY *evpRSAPrivKey = EVP_PKEY_new();
    const unsigned char *privKeyBits = (unsigned char *) [privKeyData bytes];
    int privKeyLength = (int)[privKeyData length];

    RSA *rsaPrivKey = d2i_RSAPrivateKey(NULL, &privKeyBits, privKeyLength);
    if (!rsaPrivKey) {
        if (error != NULL) { *error = [self internalError:@"d2i_RSAPrivateKey failed"]; }
        return nil;
    }
    if (!RSA_check_key(rsaPrivKey)) {
        if (error != NULL) { *error = [self internalError:@"RSA_check_key failed"]; }
        return nil;
    }

    if (!EVP_PKEY_assign_RSA(evpRSAPrivKey, rsaPrivKey)) {
        if (error != NULL) { *error = [self internalError:@"EVP_PKEY_assign_RSA failed"]; }
        return nil;
    }
    return evpRSAPrivKey;
}

+ (NSData *)BIOtoNSData:(BIO *)aBIO error:( NSError* __nullable  * __nullable)error {
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(aBIO, &mem);
    if (!mem || !mem->data || !mem->length) {
        if (error != NULL) { *error = [self internalError:@"BIO_get_mem_ptr failed"]; }
        return nil;
    }

    return [NSData dataWithBytes:mem->data length:mem->length];
}

+ (NSString *)errorString:(unsigned long)err {
    ERR_load_X509_strings();
    char buf[1024];
    ERR_error_string_n(err, (char *) &buf, 1024);
    return [NSString stringWithUTF8String:buf];
}
/*
+ (void)populateCertificate:(ExKCCertificate *)certificate fromCertificateRef:(SecCertificateRef)certRef {
    if (certRef == nil) return;
    NSData *certificateData = (__bridge_transfer NSData *) SecCertificateCopyData(certRef);
    const unsigned char *certificateDataBytes = (const unsigned char *) [certificateData bytes];
    X509 *certificateX509 = d2i_X509(NULL, &certificateDataBytes, [certificateData length]);
    NSString *subject = [self CertificateGetSubjectName:certificateX509];
    NSString *issuer = [self CertificateGetIssuerName:certificateX509];
    NSDate *expiryDate = [self CertificateGetExpiryDate:certificateX509];
    certificate.subject = subject;
    certificate.expiryDate = expiryDate;
    certificate.issuerName = issuer;
}


+ (NSString *)CertificateGetIssuerName:(X509 *)certificateX509 {
    NSString *issuer = nil;
    if (certificateX509 != NULL) {
        X509_NAME *issuerX509Name = X509_get_issuer_name(certificateX509);

        if (issuerX509Name != NULL) {
            int nid = OBJ_txt2nid("O"); // organization
            int index = X509_NAME_get_index_by_NID(issuerX509Name, nid, -1);

            X509_NAME_ENTRY *issuerNameEntry = X509_NAME_get_entry(issuerX509Name, index);

            if (issuerNameEntry) {
                ASN1_STRING *issuerNameASN1 = X509_NAME_ENTRY_get_data(issuerNameEntry);

                if (issuerNameASN1 != NULL) {
                    unsigned char *issuerName = ASN1_STRING_data(issuerNameASN1);
                    issuer = [NSString stringWithUTF8String:(char *) issuerName];
                }
            }
        }
    }

    return issuer;
}
*/

+ (NSString *)CertificateGetSubjectName:(X509 *)certificateX509 {
    NSString *subject = nil;
    if (certificateX509 != NULL) {
        X509_NAME *subjectX509Name = X509_get_subject_name(certificateX509);
        
        if (subjectX509Name != NULL) {
            int nid = OBJ_txt2nid("CN"); // common name
            int index = X509_NAME_get_index_by_NID(subjectX509Name, nid, -1);
            
            X509_NAME_ENTRY *subjectNameEntry = X509_NAME_get_entry(subjectX509Name, index);
            
            if (subjectNameEntry) {
                ASN1_STRING *subjectNameASN1 = X509_NAME_ENTRY_get_data(subjectNameEntry);
                
                if (subjectNameASN1 != NULL) {
                    unsigned char *subjectName = ASN1_STRING_data(subjectNameASN1);
                    subject = [NSString stringWithUTF8String:(char *) subjectName];
                }
            }
        }
    }
    
    return subject;
}


+ (NSDate *)CertificateGetExpiryDate:(X509 *)certificateX509 {
    NSDate *expiryDate = nil;

    if (certificateX509 != NULL) {
        ASN1_TIME *certificateExpiryASN1 = X509_get_notAfter(certificateX509);
        if (certificateExpiryASN1 != NULL) {
            ASN1_GENERALIZEDTIME *certificateExpiryASN1Generalized = ASN1_TIME_to_generalizedtime(certificateExpiryASN1, NULL);
            if (certificateExpiryASN1Generalized != NULL) {
                unsigned char *certificateExpiryData = ASN1_STRING_data(certificateExpiryASN1Generalized);

                // ASN1 generalized times look like this: "20131114230046Z"
                //                                format:  YYYYMMDDHHMMSS
                //                               indices:  01234567890123
                //                                                   1111
                // There are other formats (e.g. specifying partial seconds or
                // time zones) but this is good enough for our purposes since
                // we only use the date and not the time.
                //
                // (Source: http://www.obj-sys.com/asn1tutorial/node14.html)

                NSString *expiryTimeStr = [NSString stringWithUTF8String:(char *) certificateExpiryData];
                NSDateComponents *expiryDateComponents = [[NSDateComponents alloc] init];

                expiryDateComponents.year = [[expiryTimeStr substringWithRange:NSMakeRange(0, 4)] intValue];
                expiryDateComponents.month = [[expiryTimeStr substringWithRange:NSMakeRange(4, 2)] intValue];
                expiryDateComponents.day = [[expiryTimeStr substringWithRange:NSMakeRange(6, 2)] intValue];
                expiryDateComponents.hour = [[expiryTimeStr substringWithRange:NSMakeRange(8, 2)] intValue];
                expiryDateComponents.minute = [[expiryTimeStr substringWithRange:NSMakeRange(10, 2)] intValue];
                expiryDateComponents.second = [[expiryTimeStr substringWithRange:NSMakeRange(12, 2)] intValue];

                NSCalendar *calendar = [NSCalendar currentCalendar];
                expiryDate = [calendar dateFromComponents:expiryDateComponents];
            }
        }
    }

    return expiryDate;
}

+ (X509 *)createX509withPEMEncodedCertificateData:(NSData *)aCertificateData {
    BIO *pemDataBIO  = NULL;
    @try {
        if ((pemDataBIO = BIO_new_mem_buf((unsigned char *) [aCertificateData bytes], (unsigned int) [aCertificateData length])) == NULL) {
            NSAssert(NO, @"BIO_new_mem_buf() failed");
        }

        X509 *cert = PEM_read_bio_X509(pemDataBIO, NULL, NULL, NULL);
        if (!cert) {
            NSLog(@"PEM_read_bio_X509() failed - invalid certificate data");
        }
        return cert;
    }
    @finally {
        if (pemDataBIO) BIO_free(pemDataBIO);
    }
};


+ (nullable OpenSSLKeyPair *)keyPairFromPEMData:(nonnull NSData *)pemData
                          encryptedWithPassword:(nonnull NSString *)passphrase
                                          error:( NSError* __nullable  * __nullable)error {
    BIO *pemDataBIO = NULL;
    BIO *keyPrivOutputBIO = NULL;
    BIO *keyPubOutputBIO = NULL;
    EVP_PKEY *privateKey = NULL;
    NSError *localError = nil;

    @try {
        keyPrivOutputBIO = BIO_new(BIO_s_mem());
        keyPubOutputBIO = BIO_new(BIO_s_mem());
        const char *pass = [passphrase UTF8String];

        if ((pemDataBIO = BIO_new_mem_buf((unsigned char *) [pemData bytes], (unsigned int) [pemData length])) == NULL) {
            if (error != NULL) { *error = [self internalError:@"BIO_new_mem_buf() failed"]; }
            return nil;
        }

        if (!PEM_read_bio_PrivateKey(pemDataBIO, &privateKey, NULL, (char *) pass)) {
            ERR_print_errors_fp(stdout);
            if (error != NULL) { *error = [self invalidParameterError:@"Invalid Private Key in PEM File or Incorrect Passphrase"]; }
            return nil;
        }


        NSUInteger keySize = (unsigned int) EVP_PKEY_bits(privateKey);

        if (!i2d_PUBKEY_bio(keyPubOutputBIO, privateKey)) {
            if (error != NULL) { *error = [self internalError:@"i2d_PUBKEY_bio() failed"]; }
            return nil;
        }
        if (!i2d_PrivateKey_bio(keyPrivOutputBIO, privateKey)) {
            if (error != NULL) {  *error = [self internalError:@"i2d_PrivateKey_bio failed"]; }
            return nil;
        }
        NSData *privKeyData = [self BIOtoNSData:keyPrivOutputBIO error:&localError];

        if (!privKeyData) {
            if (error != NULL) { *error = localError; }
            return nil;
        }


        NSData *pubKeyData = [self BIOtoNSData:keyPubOutputBIO error:&localError];

        if (!pubKeyData) {
            if (error != NULL) { *error = localError; }
            return nil;
        }

        ExCryptoKeyType keyType = map_EVP_PKEY_Type(privateKey);

        if (keyType == kExCryptoKeyTypeRSA) {
            return [[OpenSSLRSAKeyPair alloc]initWithKeyLength:keySize privateKeyData:privKeyData publicKeyDataWithX509Header:pubKeyData];
        } else {
            if (error != NULL) { *error = [self unsupportedFormatError:@"Unsupported Key Type (Only RSA Supported)"]; }
            return nil;
        }
    }
    @finally {
        if (keyPubOutputBIO) BIO_free(keyPubOutputBIO);
        if (keyPrivOutputBIO) BIO_free(keyPrivOutputBIO);
        if (pemDataBIO) BIO_free(pemDataBIO);
        if (privateKey) EVP_PKEY_free(privateKey);
    }
}

+ (nullable OpenSSLIdentity *)pkcs12IdentityWithKeyPair:(nonnull OpenSSLKeyPair *)keyPair
                                            certificate:(nonnull OpenSSLCertificate *)certificate
                                protectedWithPassphrase:(nonnull NSString *)passphrase
                                                  error:( NSError* __nullable  * __nullable)error {
    EVP_PKEY *cert_privkey = NULL;
    PKCS12 *pkcs12bundle = NULL;
    X509 *cert = NULL;
    BIO *bio = NULL;
    STACK_OF(X509) *certstack = sk_X509_new_null();
    NSError *localError = nil;

    @try {

        cert_privkey = [self createEVP_PKEYfromData:keyPair.privateKeyData error:&localError];
        if (cert_privkey == NULL) {
            if (error != NULL) { *error = [self internalError:@"Could not extract private key (createEVP_PKEYfromData failed)"]; }
            return nil;
        }

        cert = [self createX509withPEMEncodedCertificateData:certificate.certificateData];
        if (cert == NULL) {
            if (error != NULL) { *error = [self internalError:@"Could not decode X509 certificate data"]; }
            return nil;
        }


        NSString *subjectName = [self CertificateGetSubjectName:cert];

        const char *pass = [passphrase UTF8String];
        const char *identityName = [subjectName UTF8String];

        pkcs12bundle = PKCS12_create(
                (char *)pass,         // certbundle access password
                (char *)identityName, // friendly certname
                cert_privkey,// the certificate private key
                cert,        // the main certificate
                certstack,   // stack of CA cert chain
                0,           // int nid_key (default 3DES)
                0,           // int nid_cert (40bitRC2)
                0,           // int iter (default 2048)
                0,           // int mac_iter (default 1)
                0            // int keytype (default no flag)
        );


        if (pkcs12bundle == NULL) {
            if (error != NULL) { *error = [self internalError:@"PKCS12_create() failed"]; }
            return nil;
        }


        bio = BIO_new(BIO_s_mem());

        if (!i2d_PKCS12_bio(bio, pkcs12bundle)) {
            if (error != NULL) { *error = [self internalError:@"i2d_PKCS12_bio() failed"]; }
            return nil;
        }
        NSData *data = [self BIOtoNSData:bio error:&localError];
        if (data == nil) {
            if (error != NULL) { *error = localError; }
            return nil;
        }
        return [[OpenSSLIdentity alloc]initWithP12EncodedIdentityData:data friendlyName:subjectName];
    }
    @finally {
        BIO_free(bio);
        PKCS12_free(pkcs12bundle);
        sk_X509_free(certstack);
        X509_free(cert);
        EVP_PKEY_free(cert_privkey);
    }


}


+ (NSError *)invalidParameterError:(NSString *)message {
    NSMutableDictionary *errorDetail = [NSMutableDictionary dictionary];
    [errorDetail setValue:message forKey:NSLocalizedDescriptionKey];
    return [NSError errorWithDomain:@"openssl" code:9997 userInfo:errorDetail];
}


+ (NSError *)unsupportedFormatError:(NSString *)message {
    NSMutableDictionary *errorDetail = [NSMutableDictionary dictionary];
    [errorDetail setValue:message forKey:NSLocalizedDescriptionKey];
    return [NSError errorWithDomain:@"openssl" code:9998 userInfo:errorDetail];
}


+ (NSError *)internalError:(NSString *)assertionError {
    NSMutableDictionary *errorDetail = [NSMutableDictionary dictionary];
    [errorDetail setValue:@"Internal Error" forKey:NSLocalizedDescriptionKey];
    [errorDetail setValue:assertionError forKey:NSLocalizedFailureReasonErrorKey];

    return [NSError errorWithDomain:@"openssl" code:9999 userInfo:errorDetail];
}





ExCryptoKeyType map_EVP_PKEY_Type(EVP_PKEY *aEVPKey) {
    switch (aEVPKey->type) {
        case EVP_PKEY_RSA:
            return kExCryptoKeyTypeRSA;
        case EVP_PKEY_DSA:
            return kExCryptoKeyTypeDSA;
        default:
            return kExCryptoKeyTypeUnknown;
    }
}


@end




