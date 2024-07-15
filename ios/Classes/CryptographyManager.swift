//
//  CryptographyManager.swift
//  local_biometric_auth
//
//  Created by Quảng Khương Duy on 13/7/24.
//

import Security
import UIKit

class CryptographyManager {
    static let shared = CryptographyManager()
    private init() {
    }
    
    func encrypt(secretKeyName: String, plainText: String) -> String? {
        if let publicKey = getPublicKey(secretKeyName: secretKeyName), let valueEncrypt = encrypt(plainText: plainText, publicKey: publicKey) {
            return valueEncrypt.base64EncodedString()
        }
        return nil
    }
    
    func decrypt(secretKeyName: String, value: String) -> String? {
        
        if let privateKey = getPrivateKey(secretKeyName: secretKeyName), let valueDecrypt = decrypt(value: value, privateKey: privateKey) {
            return valueDecrypt
        }
        return nil
    }
    
    func delete(secretKeyName: String) {
        deleteKey(tag: "\(secretKeyName)_public")
        deleteKey(tag: "\(secretKeyName)_private")
    }
    
    private func getPublicKey(secretKeyName:String) -> SecKey? {
        if let publicKey = getKeyFromKeychain(tag: "\(secretKeyName)_public") {
            return publicKey
        }
        let keys = generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: "\(secretKeyName)_public", privateTag: "\(secretKeyName)_private")
        return keys.publicKey
    }
    
    private func getPrivateKey(secretKeyName:String) -> SecKey? {
        if let privateKey = getKeyFromKeychain(tag: "\(secretKeyName)_private") {
            return privateKey
        }
        let keys = generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: "\(secretKeyName)_public", privateTag: "\(secretKeyName)_private")
        return keys.privateKey
    }
    
    private func encrypt(plainText: String, publicKey: SecKey) -> Data? {
        guard let data = plainText.data(using: .utf8) else { return nil }

        let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else { return nil }
        var error: Unmanaged<CFError>?

        guard let cipherData = SecKeyCreateEncryptedData(publicKey,
                                                         algorithm,
                                                         data as CFData,
                                                         &error) as Data? else {
                                                            print("Encryption error: \((error?.takeRetainedValue())!)")
                                                            return nil
        }

        return cipherData
    }
    
    
    private func decrypt(value: String, privateKey: SecKey) -> String? {
        
        if let cipherData = Data(base64Encoded: value, options: .ignoreUnknownCharacters) {
            let algorithm: SecKeyAlgorithm = .rsaEncryptionOAEPSHA256
            
            guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else { return nil }
            var error: Unmanaged<CFError>?
            
            guard let clearData = SecKeyCreateDecryptedData(privateKey,
                                                            algorithm,
                                                            cipherData as CFData,
                                                            &error) as Data? else {
                print("Decryption error: \((error?.takeRetainedValue())!)")
                return nil
            }
            
            return String(data: clearData, encoding: .utf8)
        }
        return nil
    }
    
    private func getKeyFromKeychain(tag: String) -> SecKey? {
        let query: [String: Any] = [ kSecClass as String: kSecClassKey,
                                     kSecAttrApplicationTag as String: tag,
                                     kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                     kSecReturnRef as String: true
                                    ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            print("Error retrieving key from keychain: \(status)")
            return nil
        }
        
        
     
        return (item as! SecKey)
    }
    
    private func deleteKey(tag:String) {
        let query: [String: Any] = [ kSecClass as String: kSecClassKey,
                                     kSecAttrApplicationTag as String: tag,
                                     kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                     kSecReturnRef as String: true
                                    ]
        SecItemDelete(query as CFDictionary)
    }
    
    private func generateKeyPairAndStoreInKeychain(keySize: Int, publicTag: String, privateTag: String) -> (publicKey: SecKey?, privateKey: SecKey?) {
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,.privateKeyUsage,nil)
     
        let publicKeyParameters: [NSObject: AnyObject] = [
            kSecAttrIsPermanent: true as AnyObject,
            kSecAttrAccessControl: access!,
            kSecAttrApplicationTag: publicTag.data(using: .utf8)! as AnyObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue
        ]
        
        let privateKeyParameters: [NSObject: AnyObject] = [
            kSecAttrIsPermanent: true as AnyObject,
            kSecAttrAccessControl : access!,
            kSecAttrApplicationTag : privateTag.data(using: .utf8)! as AnyObject,
            kSecClass: kSecClassKey, // added this value
            kSecReturnData: kCFBooleanTrue
         ]
        var parameters = [NSObject: AnyObject]()
        parameters[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        parameters[kSecAttrKeySizeInBits] = keySize as AnyObject
        parameters[kSecPublicKeyAttrs] = publicKeyParameters as AnyObject
        parameters[kSecPrivateKeyAttrs] = privateKeyParameters as AnyObject
        
        var publicKey, privateKey: SecKey?
        var error: Unmanaged<CFError>?
        if #available(iOS 15.0, *) {
            privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
            publicKey = SecKeyCopyPublicKey(privateKey!)!
        } else {
            let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
            guard status == errSecSuccess else {
                print("Error generating key pair: \(status)")
                return (nil, nil)
            }
        }
        return (publicKey, privateKey)
    }
}
