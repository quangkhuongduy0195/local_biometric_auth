//
//  KeychainManager.swift
//  local_biometric_auth
//
//  Created by Quảng Khương Duy on 12/7/24.
//

import Security
import UIKit

public class KeychainManager {
    static let shared = KeychainManager()
    let account = "BioAccount"  // An account name
    private init() {
    }
    
     func encrypt(secretKeyName: String, plainText: String) -> String? {
//         getKeyFromKeychain(tag: "\(secretKeyName)_public")
//         if let keys = getOrCreateKeys(secretKeyName: name) {
//             if let cipherData = encrypt(plainText: name, publicKey: keys.publicKey) {
                 
                 
//                 // Key to Data
//                 var error: Unmanaged<CFError>?
//                 guard let privateKeyData = SecKeyCopyExternalRepresentation(keys.privateKey, &error) as? Data else {
//                     print("Error generating key pair")
//                     return nil
//                 }
//                 print("publicKeyData: \(privateKeyData.base64EncodedString())")
//                 
//                 // Data to key
//                 let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator
//                 kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
//                 .privateKeyUsage,
//                                                              
//                 nil) // Ignore any error
//                 let options: [NSObject: AnyObject] = [
//                     kSecAttrIsPermanent: true as AnyObject,
//                     kSecAttrAccessControl : access!,
//                     kSecAttrKeyType: kSecAttrKeyTypeRSA,
//                     kSecAttrKeyClass: kSecAttrKeyClassPrivate,
//                     kSecClass: kSecClassKey, // added this value
//                     kSecReturnData: kCFBooleanTrue
//                 ]
//                 guard let key = SecKeyCreateWithData(privateKeyData as CFData,
//                                                      options as CFDictionary,
//                                                      &error) else {
//                     print("Error generating key pair")
//                     return nil
//                 }
                    
                 
                 
//                 print(cipherData.base64EncodedString())
//                 let plainText = decrypt(cipherData: cipherData, privateKey: keys.privateKey)
//                 print(plainText ?? "plainText empty")
//             }
//         }
//        let keys = generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: "\(name)_public", privateTag:   "\(name)_private")
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
    
    func getPublicKey(secretKeyName:String) -> SecKey? {
        if let publicKey = getKeyFromKeychain(tag: "\(secretKeyName)_public") {
            return publicKey
        }
        let keys = generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: "\(secretKeyName)_public", privateTag: "\(secretKeyName)_private")
        return keys.publicKey
    }
    
    func getPrivateKey(secretKeyName:String) -> SecKey? {
        if let privateKey = getKeyFromKeychain(tag: "\(secretKeyName)_private") {
            return privateKey
        }
        let keys = generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: "\(secretKeyName)_public", privateTag: "\(secretKeyName)_private")
        return keys.privateKey
    }
    
    func encrypt(plainText: String, publicKey: SecKey) -> Data? {
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
    
    
    func decrypt(value: String, privateKey: SecKey) -> String? {
        
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
    
    func getOrCreateKeys(secretKeyName:String) -> (publicKey:SecKey, privateKey:SecKey)? {
        if let publicKey = getKeyFromKeychain(tag: "\(secretKeyName)_public"), let privateKey = getKeyFromKeychain(tag: "\(secretKeyName)_private") {
            return (publicKey , privateKey)
        }
        let keys = generateKeyPairAndStoreInKeychain(keySize: 2048, publicTag: "\(secretKeyName)_public", privateTag:   "\(secretKeyName)_private")
        return keys as? (publicKey: SecKey, privateKey: SecKey)
    }
    
    func getKeyFromKeychain(tag: String) -> SecKey? {
     let query: [String: Any] = [
     kSecClass as String: kSecClassKey,
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
    
    func generateKeyPairAndStoreInKeychain(keySize: Int, publicTag: String, privateTag: String) -> (publicKey: SecKey?, privateKey: SecKey?) {
     let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator
     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
     .privateKeyUsage,
     nil) // Ignore any error
     
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
     let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
     
     guard status == errSecSuccess else {
     print("Error generating key pair: \(status)")
     return (nil, nil)
     }
     
     return (publicKey, privateKey)
    }
    
    func storeLoginInfo(serviceName: String, password: String) {
        DispatchQueue.global().async {
            let service = serviceName  // A service name for your app
            let passwordData = password.data(using: .utf8)
            if let passwordData = passwordData {
                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: self.account,
                    kSecValueData as String: passwordData
                ]
                SecItemDelete(query as CFDictionary)  // Delete any existing data
                let status = SecItemAdd(query as CFDictionary, nil)
                if status == errSecSuccess {
                    print("Login information securely stored.")
                } else {
                    print("Failed to store login information securely.")
                }
            }
        }
    }
    
    
    func retrieveLoginInfo(serviceName: String,completion: @escaping (String?, Error?) -> Void) {
        let service = serviceName
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: self.account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        // Use kSecReturnAttributes to retrieve attributes like email and username.
        query[kSecReturnAttributes as String] = true
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess, let retrievedData = dataTypeRef as? [String: Any],
           let passwordData = retrievedData[kSecValueData as String] as? Data,
           let password = String(data: passwordData, encoding: .utf8) {
            // Successfully retrieved email and password
            completion(password, nil)
        } else if let error = SecCopyErrorMessageString(status, nil) as String? {
            // Handle the error
            completion(nil, NSError(domain: "KeychainErrorDomain", code: Int(status), userInfo: [NSLocalizedDescriptionKey: error]))
        } else {
            // Handle the case where retrieval fails
            completion(nil, NSError(domain: "KeychainErrorDomain", code: Int(status), userInfo: nil))
        }
    }
    
    
}
