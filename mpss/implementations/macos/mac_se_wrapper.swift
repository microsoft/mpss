// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

import Foundation
import CryptoKit
import Security
import os

// The dispatch queue is used to serialize access to the key store, in order to make it thread-safe.
private let _keyStoreQueue = DispatchQueue(label: "com.microsoft.mpss.KeyStore")

// In-memory dictionary that will contain currently open keys
nonisolated(unsafe) private let _keyStore = NSMutableDictionary()


let KeyChainAccountName = "P256Key"
let ErrorKey = "com.microsoft.mpss.ErrorKey";

/// Get the current last error
/// - Returns: The current last error
private func getError() -> String {
    Thread.current.threadDictionary[ErrorKey] as? String ?? "[No error]";
}

/// Set the current last error
/// - Parameters:
///     - error: The new last error
private func setError(_ error: String) {
    Thread.current.threadDictionary[ErrorKey] = error;
}

/// Store a private key in the in-memory dictionary.
/// - Parameters:
///     - keyName: Name of the key to store
///     - key: The private key to store
private func storeKeyInDict(keyName: String, key: SecureEnclave.P256.Signing.PrivateKey) {
    _keyStoreQueue.sync {
        _keyStore[keyName] = key
    }
}

/// Get a private ke3y from the in-memory dictionary.
/// - Parameters:
///      - keyName: Name of the key to retrieve
/// - Returns: Private key if found, nil otherwise
private func getKeyFromDict(keyName: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    return _keyStoreQueue.sync(execute: {
        guard let result = _keyStore.value(forKey: keyName) as? SecureEnclave.P256.Signing.PrivateKey? else {
            setError("Did not find key with name \(keyName)")
            return nil
        }
        return result
    })
}

/// Remove private key from in-memory dictionary
/// - Parameters:
///     - keyName: Name of the key to remove
private func removeKeyFromDict(_ keyName: String) {
    _keyStoreQueue.sync {
        _keyStore.removeObject(forKey: keyName)
    }
}

/// Get a private key.
/// Will try to get from in-memory dictionary, if not found will try to recreate from data in Keychain.
///  - Parameters:
///      - keyName: Name of the key to retrieve
/// - Returns: Private key, or nil if not found
private func getKey(_ keyName: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    do {
        // Try first from dictionary
        var result = getKeyFromDict(keyName: keyName)
        if result == nil {
            // Try from keychain
            os_log("Key %s not found in dictionary, trying to get from Keychain", keyName)
            let keyChainData = retrieveDataFromKeychain(account: KeyChainAccountName, service: keyName)
            if keyChainData == nil {
                // No key.
                os_log("Key %s not found in Keychain", keyName)
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
        setError("Error trying to get key: \(error)")
        return nil
    }
}

/// Store data in the keychain
/// - Parameters:
///     - data: The data to store
///     - account: The account name under which the data will be stored
///     - service: The service name under which the data will be stored
/// - Returns: OSStatus that indicates the result of the operation
private func storeDataInKeychain(data: Data, account: String, service: String) -> OSStatus {
    // Define the Keychain query dictionary
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecValueData as String: data
    ]
    
    // In case the item already exists, delete it before adding the new one
    removeDataFromKeyChain(account: account, service: service)
    
    // Add new data to the Keychain
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecSuccess {
        // Successfully added
        os_log("Successfully added item to Keychain")
    } else if status == errSecDuplicateItem {
        // Item already exists
        os_log("Item already exists in Keychain")
    } else {
        // Some other error occurred
        os_log("Error adding item to Keychain: %d", status)
    }

    return status
}

/// Retrieve data from the keychain
/// - Parameters:
///     - account: The account name under which the data can be found
///     - service: The service name under which the data can be found
/// - Returns: The data retrieved from the keychain or nil if not found
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
    if status == errSecSuccess {
        // Successfully retrieved
        os_log("Successfully retrieved item from Keychain")
    } else if status == errSecItemNotFound {
        // Item not found
        os_log("Item not found in Keychain")
        return nil
    } else {
        // Some other error occurred
        os_log("Error retrieving item from Keychain: %d", status)
        return nil
    }
    
    guard status == errSecSuccess, let retrievedData = item as? Data else {
        return nil
    }
    
    return retrievedData
}

/// Remove data from the keychain
/// - Parameters:
///     - account: The account name under which the data can be found
///     - service: The service name under which the data can be found
private func removeDataFromKeyChain(account: String, service: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service
    ]
    
    let status = SecItemDelete(query as CFDictionary)

    if status == errSecSuccess {
        // Successfully deleted
        os_log("Successfully deleted item from Keychain")
    } else if status == errSecItemNotFound {
        // Item not found, nothing to delete
        os_log("Item not found in Keychain, nothing to delete")
    } else {
        // Some other error occurred
        os_log("Error deleting item from Keychain: %d", status)
    }
}

/// Get a full key name from a user key name.
/// The full key name includes a prefix for MPSS.
/// - Parameters:
///     - keyName: The user provided key name
/// - Returns: The key name including the MPSS prefix
private func getKeyName(_ keyName: String) -> String {
    let result = "com.microsoft.mpss.\(keyName)"
    return result
}

/// Create a random P256 private key in the Secure Enclave
/// - Parameters:
///     - keyName: Name that identifies the private key
/// - Returns: Random private key, or nil if it could not be created
private func createKeyPriv(_ keyName: String) -> SecureEnclave.P256.Signing.PrivateKey? {
    do {
        // Configure Keychain access requirements
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ) else {
            setError("Unable to create SecAccessControl")
            return nil
        }
        
        // Does not exist, create it
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        
        // Save it now
        _ = storeDataInKeychain(data: privateKey.dataRepresentation, account: KeyChainAccountName, service: keyName)
        storeKeyInDict(keyName: keyName, key: privateKey)
        
        return privateKey
    } catch {
        setError("Error creating key: '\(error)'")
        return nil
    }
}

/// Whether a secure enclave is available
/// - Returns: true if the secure enclave is available, false otherwise
@_cdecl("MPSS_SE_SecureEnclaveIsSupported")
func isSupported() -> Bool {
    return SecureEnclave.isAvailable
}

/// Open an existing private key.
/// - Parameters:
///     - keyName: Name of the private key to open
/// - Returns: True if key was opened successfully, False otherwise
@_cdecl("MPSS_SE_OpenExistingKey")
func openExistingKey(_ keyName: UnsafePointer<CChar>) -> Bool {
    let keyNameString = String(cString: keyName)
    return openExistingKey(keyNameString)
}

/// Open an existing private key.
/// - Parameters:
///     - keyName: Name of the private key to open
/// - Returns: True if key was opened successfully, False otherwise
private func openExistingKey(_ keyName: String) -> Bool {
    let fullKeyName = getKeyName(keyName)
    let existing = getKey(fullKeyName)
    return (existing != nil)
}

/// Remove existing key
/// Will remove existing key from the in-memory dictionary and its representation from Keychain
/// - Parameters:
///     - keyName: Name of the key to remove
@_cdecl("MPSS_SE_RemoveExistingKey")
func removeExistingKey(_ keyName: UnsafePointer<CChar>) {
    let keyNameString = String(cString: keyName)
    removeExistingKey(keyNameString)
}

/// Remove existing key
/// Will remove existing key from the in-memory dictionary and its representation from Keychain
/// - Parameters:
///     - keyName: Name of the key to remove
private func removeExistingKey(_ keyName: String) {
    let fullKeyName = getKeyName(keyName)
    removeKeyFromDict(fullKeyName)
    removeDataFromKeyChain(account: KeyChainAccountName, service: fullKeyName)
}

/// Close existing key
/// Will remove existing key from the in-memory dictionary.
@_cdecl("MPSS_SE_CloseKey")
func closeKey(_ keyName: UnsafePointer<CChar>) {
    let keyNameString = String(cString: keyName)
    let fullKeyName = getKeyName(keyNameString)
    removeKeyFromDict(fullKeyName)
}

/// Create a random P256 private key in the Secure Enclave
/// - Parameters:
///     - keyName: Name that identifies the created key
/// - Returns: True if key was created successfully, False otherwise
@_cdecl("MPSS_SE_CreateKey")
func createKey(_ keyName: UnsafePointer<CChar>) -> Bool {
    let keyNameString = String(cString: keyName)
    return createKey(keyNameString)
}

/// Create a random P256 private key in the Secure Enclave
/// - Parameters:
///     - keyName: Name that identifies the created key
/// - Returns: True if key was created successfully, False otherwise
private func createKey(_ keyName: String) -> Bool {
    let fullKeyName = getKeyName(keyName)
    let privateKey = createKeyPriv(fullKeyName)
    return (privateKey != nil)
}

/// Sign a hash with the given private key
/// - Parameters:
///     - keyName: Name that identifies the private key to use
///     - hash: Buffer that contains the hash to sign
///     - hashLength: Size of the hash buffer
///     - sig: Buffer that will receive the signature
///     - sigLength: Size of the signature buffer. Will be updated with the number of bytes written to the signature buffer.
/// - Returns: True if the signature was created successfully, False otherwise
@_cdecl("MPSS_SE_Sign")
func sign(_ keyName: UnsafePointer<CChar>, hash: UnsafePointer<UInt8>, hashLength: UInt, sig: UnsafeMutablePointer<UInt8>, sigLength: UnsafeMutablePointer<UInt>) -> Bool {
    let keyNameString = String(cString: keyName)
    let hashData = Data(bytes: hash, count: Int(hashLength))
    
    guard let signature = sign(keyName: keyNameString, hash: hashData) else {
        return false
    }

    if signature.count > Int(sigLength.pointee) {
        // Not enough space in buffer
        setError("Not enough space in signature buffer. Got: \(sigLength.pointee), need: \(signature.count)")
        return false
    }

    sigLength.pointee = UInt(signature.count)
    signature.copyBytes(to: sig, count: signature.count)
    
    return true
}

/// Sign a hash with the given private key
/// - Parameters:
///     - keyName: Name that identifies the private key to use
///     - hash: The hash to sign
/// - Returns: Data that contains the signature, or nil if failed to sign
private func sign(keyName: String, hash: Data) -> Data? {
    do {
        let fullKeyName = getKeyName(keyName)
        
        // Try to get existing key
        guard let privateKey = getKey(fullKeyName) else {
            // Key should exist
            setError("Could not get key: \(keyName)")
            return nil
        }
        
        let signature = try privateKey.signature(for: hash)
        
        return signature.derRepresentation
    } catch {
        setError("Error trying to sign hash: \(error)")
        return nil
    }
}

/// Verify the given signature of the given hash using the given private key
/// - Parameters:
///     - keyName: Name of the key to use for verification
///     - hash: Buffer with the hash to verify
///     - hashLength: Size of the hash buffer
///     - signature: Buffer with the signature to verify
///     - signatureLength: Size of the signature buffer
/// - Returns: True if the signature was verified correctly, False otherwise
@_cdecl("MPSS_SE_VerifySignature")
func verifySignature(keyName: UnsafePointer<CChar>, hash: UnsafePointer<UInt8>, hashLength: UInt, signature: UnsafePointer<UInt8>, signatureLength: UInt) -> Bool {
    let keyNameString = String(cString: keyName)
    let hashData = Data(bytes: hash, count: Int(hashLength))
    let signatureData = Data(bytes: signature, count: Int(signatureLength))
    
    return verifySignature(keyName: keyNameString, hash: hashData, signature: signatureData)
}

/// Verify the given signature of the given hash using the given private key
/// - Parameters:
///     - keyName: Name of the key to use for verification
///     - hash: Hash to verify
///     - signature: Signature to verify
/// - Returns: True if the signature was verified correctly, False otherwise
private func verifySignature(keyName: String, hash: Data, signature: Data) -> Bool {
    do {
        let fullKeyName = getKeyName(keyName)
        guard let privateKey = getKey(fullKeyName) else {
            setError("Could not get key: \(keyName)")
            return false
        }
        
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        return privateKey.publicKey.isValidSignature(ecdsaSignature, for: hash)
    }
    catch {
        setError("Error verifying signature: \(error)")
        return false
    }
}

/// Verify the given signature of the given hash using the given public key
/// - Parameters:
///     - pk: Buffer with the public key to use for verification
///     - pkLength: Size of the public key buffer
///     - hash: Buffer with the hash to verify
///     - hashLength: Size of the hash buffer
///     - signature: Buffer with the signature to verify
///     - signatureLength: Size of the signature buffer
/// - Returns: True if the signature was verified successfully, False otherwise
@_cdecl("MPSS_SE_VerifyStandaloneSignature")
func verifyStandaloneSignature(pk: UnsafePointer<UInt8>, pkLength: UInt, hash: UnsafePointer<UInt8>, hashLength: UInt, signature: UnsafePointer<UInt8>, signatureLength: UInt) -> Bool {
    let pkData = Data(bytes: pk, count: Int(pkLength))
    let hashData = Data(bytes: hash, count: Int(hashLength))
    let signatureData = Data(bytes: signature, count: Int(signatureLength))
    
    return verifyStandaloneSignature(pk: pkData, hash: hashData, signature: signatureData)
}

/// Verify the given signature of the given hash using the given public key
/// - Parameters:
///     - pk: Data representation of the public key
///     - hash: Data of the hash to verify
///     - signature: Data of the signature to verify
/// - Returns: True if the signature was verified successfully, False otherwise
private func verifyStandaloneSignature(pk: Data, hash: Data, signature: Data) -> Bool {
    do {
        // Recreate public key
        let publicKey = try P256.Signing.PublicKey.init(x963Representation: pk)
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        
        return publicKey.isValidSignature(ecdsaSignature, for: hash)
    } catch {
        setError("Error verifying signature: \(error)")
        return false
    }
}

/// Get x9.63 representation of the public key of the given private key
/// - Parameters:
///     - keyName: Name of the private key
///     - pk: Buffer that will receive the public key representation
///     - pkLength: Size of the public key buffer. Will be updated with the bytes written to the buffer.
/// - Returns: True if the public key representation was obtained successfully, False otherwise
@_cdecl("MPSS_SE_GetPublicKey")
func getPublicKey(keyName: UnsafePointer<CChar>, pk: UnsafeMutablePointer<UInt8>, pkLength: UnsafeMutablePointer<UInt>) -> Bool {
    let keyNameString = String(cString: keyName)
    
    guard let publicKey = getPublicKey(keyName: keyNameString) else {
        return false
    }
    
    if publicKey.count > pkLength.pointee {
        // Not enough space
        setError("Not enough space to store public key. Got: \(pkLength.pointee), needed: \(publicKey.count)")
        return false
    }
    
    publicKey.copyBytes(to: pk, count: publicKey.count)
    pkLength.pointee = UInt(publicKey.count)
    
    return true
}

/// Get x9.63 representation of the public key of the given private key
/// - Parameters:
///     - keyName: Name of the private key
/// - Returns: x9.63 representation of the public key, nil if not able to get representation
private func getPublicKey(keyName: String) -> Data? {
    let fullKeyName = getKeyName(keyName)
    guard let privateKey = getKey(fullKeyName) else {
        setError("Could not get private key: \(keyName)")
        return nil
    }
    
    let publicKey = privateKey.publicKey
    return publicKey.x963Representation
}

/// Get last error
/// - Parameters:
///     - error: Buffer where last error will be written
///     - errorLength: Size of the error buffer
/// - Returns: If error is nil: Size of the buffer needed to write the last error. If error is not nil, bytes written to error buffer. If not enough space to write error, will return 0
@_cdecl("MPSS_SE_GetLastError")
func getLastError(error: UnsafeMutablePointer<CChar>?, errorLength: UInt) -> UInt
{
    let lastError = getError()
    
    // Return string size if error is nil
    if error == nil {
        return UInt(lastError.count)
    }
    
    if lastError.count > Int(errorLength) {
        // Not enough space
        return 0
    }
    
    _ = lastError.withCString { cString in
        strncpy(error!, cString, lastError.count)
    }
    
    return UInt(lastError.count)
}
