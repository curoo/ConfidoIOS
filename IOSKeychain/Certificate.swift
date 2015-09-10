//
//  Certificate.swift
//
//  Created by Rudolph van Graan on 23/08/2015.
//

import Foundation

public class Certificate : KeychainItem {
    var secCertificate: SecCertificate?
    public private(set) var subject: String?
    var issuerName: String?
    var serialNumber: NSData?
    var certificateType: NSNumber?
    var expiryDate: NSDate?


    public class func certificate(derEncodedCertificateData: NSData) -> Certificate? {
        let secCertificate = SecCertificateCreateWithData(nil, derEncodedCertificateData)
        if secCertificate != nil {
            return Certificate(secCertificate: secCertificate.takeRetainedValue())
        }
        return nil;
    }

    public init(secCertificate: SecCertificate) {
        super.init(securityClass: .Certificate, attributeBag: nil)
        self.secCertificate = secCertificate
        let unManagedSubjectSummary = SecCertificateCopySubjectSummary(secCertificate)
        self.subject = unManagedSubjectSummary.takeRetainedValue() as String
    }
}

//public class Certificate: KeyChainItem {
//    var secCertificate: SecCertificate
//    var subject: String?
//    var issuerName: String?
//    var serialNumber: NSData?
//    var certificateType: NSNumber?
//    var expiryDate: NSDate?
//
//    override public class var secClass: CFString! {
//        return kSecClassCertificate;
//    }
//
//    public func certificate(label: String)-> Certificate? {
//        return nil;
//    }
//
//
//    public init(resourceName: String, fileType:String, inBundle bundle: NSBundle) {
//
//    }
//
//
//    public init(certificateData data:NSData, fileType: String) {
//    }
//
//    override func setItemPropertiesFromKeychain(properties: [ String: AnyObject ]) {
//        super.setItemPropertiesFromKeychain(properties)
//        certificateType = properties[String(kSecAttrCertificateType)] as? NSNumber;
//        serialNumber = properties[String(kSecAttrSerialNumber)] as? NSData;
//        let valueObject : AnyObject! = properties[String(kSecValueRef)]
//        if CFGetTypeID(valueObject) == SecIdentityGetTypeID() {
//            let identityRef : Unmanaged<SecIdentity> =  Unmanaged.fromOpaque(valueObject)
//            var returnedCertificate: Unmanaged<SecCertificate>? = nil
//            let status = SecIdentityCopyCertificate(identityRef, &returnedCertificate)
//            assert(status == 0)
//            secCertificate = returnedCertificate!.takeRetainedValue()
//        } else if CFGetTypeID(valueObject) == SecCertificateGetTypeID() {
//            secCertificate = valueObject as! SecCertificate
//        } else {
//            return
//        }
//        self.subject = SecCertificateCopySubjectSummary(certificate) as String
//        //[OpenSSLSupport populateCertificate:self fromCertificateRef:tempCertificateRef];
//        if (tempCertificateRef) {
//            self.itemSecRef = tempCertificateRef;
//            CFRetain(self.itemSecRef)
//    }
//
//    - (void)setItemPropertiesFromMetaData:(NSDictionary *)properties {
//    [super setItemPropertiesFromMetaData:properties];
//    self.certificateType = properties[(__bridge id) kSecAttrCertificateType];
//    self.serialNumber = properties[(__bridge id) kSecAttrSerialNumber];
//
//    CFTypeRef valueRef = (__bridge CFTypeRef) properties[(__bridge id) kSecValueRef];
//
//    SecCertificateRef tempCertificateRef;
//    if (CFGetTypeID(valueRef) == SecIdentityGetTypeID()) {
//    OSStatus status =  SecIdentityCopyCertificate((SecIdentityRef)valueRef, &tempCertificateRef);
//    NSAssert(status == 0,@"Status =/= 0");
//    } else if (CFGetTypeID(valueRef) == SecCertificateGetTypeID()) {
//    tempCertificateRef = (SecCertificateRef)valueRef;
//    } else {
//    NSAssert(false, @"Unknown value ref type");
//    }
//    NSString *subjectSummary = (__bridge NSString *)(SecCertificateCopySubjectSummary ( tempCertificateRef));
//    [OpenSSLSupport populateCertificate:self fromCertificateRef:tempCertificateRef];
//    self.subject = subjectSummary;
//    if (tempCertificateRef) {
//    self.itemSecRef = tempCertificateRef;
//    CFRetain(self.itemSecRef);
//    }
//
//    }
//
