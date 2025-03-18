//
//  secure_enclave_keys.swift
//  KeyCreatorSW
//
//  Created by Radames Cruz Moreno on 3/17/25.
//

import Foundation
import CryptoKit
import Security

private let _keyStoreQueue = DispatchQueue(label: "com.microsoft.mpss.KeyStore")
private var _keyStore = NSMutableDictionary()

let KeyChainAccountName = "P256Key"

private func storeKeyInDict(keyName: String, key: SecureEnclave.P256.Signing.PrivateKey) {
    _keyStoreQueue.sync {
        _keyStore[keyName] = key
    }
}

private func getKeyFromDict(keyName: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    return _keyStoreQueue.sync(execute: {
        guard let result = _keyStore.value(forKey: keyName) as? SecureEnclave.P256.Signing.PrivateKey? else {
            print("Did not find key with name", keyName)
            return nil
        }
        return result
    })
}

private func removeKeyFromDict(_ keyName: String) {
    _keyStoreQueue.sync {
        _keyStore.removeObject(forKey: keyName)
    }
}

private func getKey(_ keyName: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    do {
        // Try first from dictionary
        var result = getKeyFromDict(keyName: keyName)
        if result == nil {
            // Try from keychain
            let keyChainData = retrieveDataFromKeychain(account: KeyChainAccountName, service: keyName)
            if keyChainData == nil {
                // No key.
                return nil
            }
            
            result = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyChainData!)
            
            // Store in dictionary for next time
            if result != nil {
                storeKeyInDict(keyName: keyName, key: result!)
            }
        }
        
        return result
    } catch {
        print("Error trying to get key: \(error)")
        return nil
    }
}

private func storeDataInKeychain(data: Data, account: String, service: String) -> OSStatus {
    // Define the Keychain query dictionary
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecValueData as String: data
    ]
    
    // In case the item already exists, delete it before adding the new one
    SecItemDelete(query as CFDictionary)
    
    // Add new data to the Keychain
    let status = SecItemAdd(query as CFDictionary, nil)
    return status
}

private func retrieveDataFromKeychain(account: String, service: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        
        // We want the data itself returned
        kSecReturnData as String: kCFBooleanTrue as Any,
        
        // Match only one item
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    
    guard status == errSecSuccess, let retrievedData = item as? Data else {
        return nil
    }
    
    return retrievedData
}

private func removeDataFromKeyChain(account: String, service: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        
        // We want the data itself returned
        kSecReturnData as String: kCFBooleanTrue as Any,
        
        // Match only one item
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    
    let _ = SecItemDelete(query as CFDictionary)
}

private func getKeyName(_ keyName: String) -> String {
    let result = "com.microsoft.mpss.\(keyName)"
    return result
}

private func createKeyPriv(_ keyName: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    do {
        // Configure Keychain access requirements
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ) else {
            print("Unable to create SecAccessControl")
            return nil
        }
        
        // Does not exist, create it
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        
        // Save it now
        _ = storeDataInKeychain(data: privateKey.dataRepresentation, account: KeyChainAccountName, service: keyName)
        
        return privateKey
    } catch {
        print("Error creating key: '\(error)'")
        return nil
    }
}

func isSupported() -> Bool {
    return SecureEnclave.isAvailable
}

func openExistingKey(_ keyName: String) -> Bool {
    let fullKeyName = getKeyName(keyName)
    let existing = getKey(fullKeyName)
    return (existing != nil)
}

func removeExistingKey(_ keyName: String) {
    let fullKeyName = getKeyName(keyName)
    removeKeyFromDict(keyName)
    removeDataFromKeyChain(account: KeyChainAccountName, service: fullKeyName)
}

func createKey(_ keyName: String) {
    let fullKeyName = getKeyName(keyName)
    let _ = createKeyPriv(fullKeyName)
}

func sign(keyName: String, hash: Data) -> Data? {
    do {
        let fullKeyName = getKeyName(keyName)
        
        // Try to get existing key
        guard let privateKey = getKey(fullKeyName) else {
            // Key should exist
            print("Could not get key: \(keyName)")
            return nil
        }
        
        let signature = try privateKey.signature(for: hash)
        
        return signature.rawRepresentation
    } catch {
        print("Error trying to sign hash: \(error)")
        return nil
    }
}

func verifySignature(keyName: String, hash: Data, signature: Data) -> Bool {
    do {
        let fullKeyName = getKeyName(keyName)
        guard let privateKey = getKey(fullKeyName) else {
            print("Could not get key: \(keyName)")
            return false
        }
        
        let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return privateKey.publicKey.isValidSignature(ecdsaSignature, for: hash)
    }
    catch {
        print("Error verifying signature: \(error)")
        return false;
    }
}

func getPublicKey(keyName: String) -> Data? {
    let fullKeyName = getKeyName(keyName)
    guard let privateKey = getKey(fullKeyName) else {
        print("Could not get private key: \(keyName)")
        return nil
    }
    
    let publicKey = privateKey.publicKey
    return publicKey.x963Representation
}

