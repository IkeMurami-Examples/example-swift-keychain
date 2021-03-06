//
//  Keychain.swift
//  TestUIKitApp
//
//  Created by Oleg Petrakov on 04.03.2021.
//

import Foundation
import Security

class SwiftKeychainTest {
    /*
     Функция-враппер, которая кладет определенный тип записи в keychain
     */
    func put(type: String, key: String, data: String) -> Int {
        switch type {
        case "password":
            return putPassword(key: key, data: data)
        case "asym_keys":
            return genAndPutAsymKeys(privateTagData: key, publicTagData: data)
        default:
            print("Type Query Not Found")
            return -1
        }
    }
    
    /*
     Кладем пароль
     */
    func putPassword(key: String, data: String) -> Int {
        let keychainItemQuery = [
            kSecValueData: data.data(using: .utf8)!,
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: key
        ] as CFDictionary
        
        let status = SecItemAdd(keychainItemQuery, nil)
        
        print("I'm put password to keychain")
        return statusParse(status: status)
        
    }
    
    /*
     Кладем асимметричные ключи шифрования и получаем их в виде строк
     */
    func genAndPutAsymKeys(privateTagData: String, publicTagData: String) -> Int {
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        let access =
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            .privateKeyUsage,
                                            nil)!
        
        let privateKeyDictionary = [
            kSecAttrIsPermanent: YESSTR,
            kSecAttrApplicationTag: privateTagData.data(using: .utf8)!,
            kSecReturnData: YESSTR,
            kSecClass: kSecClassKey,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrTokenID as String:            kSecAttrTokenIDSecureEnclave, // Generate key into Secure Enclave
            kSecAttrAccessControl: access  // For storeing into Secure Enclave
        ] as CFDictionary
        
        let publicKeyDictionary = [
            kSecAttrIsPermanent: YESSTR,
            kSecAttrApplicationTag: publicTagData.data(using: .utf8)!,
            kSecReturnData: YESSTR,
            kSecClass: kSecClassKey,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ] as CFDictionary
        
        let keyPairDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecPrivateKeyAttrs: privateKeyDictionary,
            kSecPublicKeyAttrs: publicKeyDictionary
        ] as CFDictionary
        
        var error: Unmanaged<CFError>?
        guard let privateKey1 = SecKeyCreateRandomKey(keyPairDictionary, &error) else {
            return -1
        }
        let out11 = SecKeyCopyExternalRepresentation(privateKey1, nil)
        print("Test private key SE  — \(out11)")
        
        let status = SecKeyGeneratePair(keyPairDictionary, &publicKey, &privateKey)
        
        print("I'm gen keys and put to keychain")
        let out = SecKeyCopyExternalRepresentation(privateKey!, nil)
        print("Test private key — \(out)")
        let out2 = SecKeyCopyExternalRepresentation(publicKey!, nil)
        print("Test public key — \(out2)")
        
        print("WTF Status: \(getPrivateKeyFromKeychain())")
        return statusParse(status: status)
    }
    
    func getPrivateKeyFromKeychain() -> Int {
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: "private_key",
                                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                    kSecReturnRef as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return statusParse(status: status)
        
        let key = item as! SecKey
        
        let out = SecKeyCopyExternalRepresentation(key, nil)
        print("WTF: Test private key — \(out)")
        // return status
        
    }
    
    /*
     Кладем симметричные ключи шифрования и получаем их в виде строк
     */
    func genAndPutSymKeys() -> Int {
        return 0
    }
    
    /*
     Обрабатываем статус
     */
    func statusParse(status: OSStatus) -> Int {
        guard status != errSecDuplicateItem else {
            print("Item already exist")
            return 0
        }
        
        guard status == errSecSuccess else {
            print("Operation finished with status: \(status)")
            return -1
        }
        
        print("Success")
        return 0
    }
    
}

