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
        let access =
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            .privateKeyUsage,
                                            nil)!
        let attributes: [String: Any] = [
          kSecAttrKeyType as String:            kSecAttrKeyTypeEC,
          kSecAttrKeySizeInBits as String:      256,//256,
          kSecAttrTokenID as String:            kSecAttrTokenIDSecureEnclave,
          kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String:      true,
            kSecAttrApplicationTag as String:   privateTagData,
            kSecAttrAccessControl as String:    access
          ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return -1
        }
        print("Test private key SE  — \(privateKey)")
        let out = SecKeyCopyExternalRepresentation(privateKey, nil)
        print("Test private key SE repr  — \(out)")
        return 0
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

