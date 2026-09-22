// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

import CryptoKit
import Foundation
import Security

// C logging functions from mpss/log_c.h, resolved at link time. The attribute carries the C
// symbol, so the Swift name beside it is local and has no bearing on linkage.
@_silgen_name("mpss_log_debug")
private func cMpssLogDebug(_ message: UnsafePointer<CChar>)

@_silgen_name("mpss_log_trace")
private func cMpssLogTrace(_ message: UnsafePointer<CChar>)

@_silgen_name("mpss_log_warning")
private func cMpssLogWarning(_ message: UnsafePointer<CChar>)

/// Log a trace message through the unified C++ logger.
private func logTrace(_ message: String) {
    message.withCString { cMpssLogTrace($0) }
}

/// Log a debug message through the unified C++ logger.
private func logDebug(_ message: String) {
    message.withCString { cMpssLogDebug($0) }
}

/// Log a warning through the unified C++ logger.
private func logWarning(_ message: String) {
    message.withCString { cMpssLogWarning($0) }
}

// The dispatch queue is used to serialize access to the key store in order to make it thread-safe.
private let _keyStoreQueue = DispatchQueue(label: "com.microsoft.mpss.KeyStore")

// A generation identifies a cache entry, not the stored key itself. Handles save this
// number so an old handle cannot use a replacement entry or reduce its reference count.
// A new entry gets a new generation; additional opens reuse the existing generation.
//
// Deletion removes the entry even if handles remain open. Closing the last handle also
// removes the entry, but does not delete the stored key. Reopening then gets a new
// generation even though the stored key has not changed.
//
// Windows instead tracks deletions by name: only deletion assigns a new generation,
// so closing and reopening a key does not change it.
private final class CacheEntry {
    let key: SecureEnclave.P256.Signing.PrivateKey
    let generation: UInt64
    var holds: Int

    init(key: SecureEnclave.P256.Signing.PrivateKey, generation: UInt64) {
        self.key = key
        self.generation = generation
        self.holds = 0
    }
}

// In-memory dictionary that will contain currently open keys.
nonisolated(unsafe) private var _keyStore: [String: CacheEntry] = [:]
nonisolated(unsafe) private var _nextGeneration: UInt64 = 0

let keyChainAccountName = "P256Key"
let errorKey = "com.microsoft.mpss.ErrorKey"

private enum AppleOperationResult: Int32 {
    case operationalError = -1
    case expectedNegative = 0
    case success = 1
}

private enum KeychainDataResult {
    case found(Data)
    case notFound
    case failure
}

private enum KeyLookupResult {
    case found(SecureEnclave.P256.Signing.PrivateKey)
    case notFound
    case failure
}

/// Extension for Digest to create an instance from Data.
extension Digest {
    static func fromData(_ hash: Data) -> Self? {
        if hash.count != Self.byteCount {
            // Invalid hash size.
            setError("Invalid hash size: \(hash.count) (expected \(Self.byteCount))")
            return nil
        }

        let data = UnsafeMutableRawBufferPointer.allocate(byteCount: hash.count, alignment: 8)
        defer {
            data.deallocate()
        }
        // Copy the bytes from the hash into the data buffer.
        data.copyBytes(from: hash)
        return data.bindMemory(to: Self.self)[0]
    }
}

/// Get the current last error.
/// - Returns: The current last error.
private func getError() -> String {
    Thread.current.threadDictionary[errorKey] as? String ?? ""
}

/// Set the current last error.
/// - Parameters:
///     - error: The new last error.
private func setError(_ error: String) {
    Thread.current.threadDictionary[errorKey] = error
}

/// Clear the current last error.
private func clearError() {
    Thread.current.threadDictionary.removeObject(forKey: errorKey)
}

/// Store a private key in the in-memory dictionary.
/// - Parameters:
///     - keyName: Name of the key to store.
///     - key: The private key to store.
///     - generation: Non-nil means the key is being handed to a handle: a hold is taken and the
///       generation it was taken on is reported here. Nil means nothing is retained.
private func storeKeyInDict(
    keyName: String, key: SecureEnclave.P256.Signing.PrivateKey,
    generation: UnsafeMutablePointer<UInt64>?
) {
    _keyStoreQueue.sync {
        // A generation is established when the name starts being cached and kept while it stays
        // cached, so that two lookups which both miss and both store do not orphan the first one's
        // hold. Deleting drops the entry, which is what makes the next create a new generation.
        let entry: CacheEntry
        if let existing = _keyStore[keyName] {
            entry = CacheEntry(key: key, generation: existing.generation)
            entry.holds = existing.holds
        } else {
            _nextGeneration += 1
            entry = CacheEntry(key: key, generation: _nextGeneration)
        }
        _keyStore[keyName] = entry
        if let generation = generation {
            entry.holds += 1
            generation.pointee = entry.generation
        }
    }
}

/// Get a private key from the in-memory dictionary.
/// - Parameters:
///      - keyName: Name of the key to retrieve.
///      - generation: Non-nil means the key is being handed to a handle, as in storeKeyInDict.
/// - Returns: Private key if found, nil otherwise.
private func getKeyFromDict(
    keyName: String, generation: UnsafeMutablePointer<UInt64>?
) -> SecureEnclave.P256.Signing.PrivateKey? {
    return _keyStoreQueue.sync(execute: {
        guard let entry = _keyStore[keyName] else {
            return nil
        }
        if let generation = generation {
            entry.holds += 1
            generation.pointee = entry.generation
        }
        return entry.key
    })
}

/// Release one hold on a key in the in-memory dictionary, evicting it once none are left.
/// Entries are reference-counted rather than name-keyed alone: two handles can be open on one
/// name, and evicting on the first close would send the survivor back to the storage lookup,
/// where a different key could answer to that name.
/// - Parameters:
///     - keyName: Name of the key to release.
private func removeKeyFromDict(_ keyName: String, _ generation: UInt64) {
    _keyStoreQueue.sync {
        guard let entry = _keyStore[keyName], entry.generation == generation else {
            // The hold was taken on an entry this name has since moved past, so there is nothing of
            // this handle's left to give up and whatever holds the name now belongs to someone else.
            return
        }
        entry.holds -= 1
        if entry.holds <= 0 {
            _keyStore.removeValue(forKey: keyName)
        }
    }
}

/// Drop a key from the in-memory dictionary regardless of how many holds remain. Deleting a key
/// invalidates every handle to it, so the entry must not survive on another handle's hold.
/// - Parameters:
///     - keyName: Name of the key to drop.
private func purgeKeyFromDict(_ keyName: String) {
    _keyStoreQueue.sync {
        _keyStore.removeValue(forKey: keyName)
    }
}

/// Fetch a cached key only while the caller's generation still names the entry. Handle operations
/// use this so that a name deleted and created again cannot be reached through a handle opened on
/// the key that used to hold it. There is deliberately no fall back to the Keychain: a handle whose
/// entry is gone is finished, not something to resolve again.
/// - Parameters:
///     - keyName: Name of the key to retrieve.
///     - generation: The generation the handle recorded when it opened.
/// - Returns: Private key if the generation still names the entry, nil otherwise.
private func getKeyForGeneration(_ keyName: String, _ generation: UInt64)
    -> SecureEnclave.P256.Signing.PrivateKey?
{
    return _keyStoreQueue.sync {
        guard let entry = _keyStore[keyName], entry.generation == generation else {
            return nil
        }
        return entry.key
    }
}

/// Whether the generation a handle recorded still names what this name holds.
@_cdecl("MPSS_SE_GenerationIsCurrent")
func generationIsCurrent(_ keyName: UnsafePointer<CChar>, _ generation: UInt64) -> Bool {
    let fullKeyName = getKeyName(String(cString: keyName))
    let superseded = _keyStoreQueue.sync {
        if let entry = _keyStore[fullKeyName] {
            return entry.generation != generation
        }
        return false
    }

    // Absence is not a supersession. It is also what a delete leaves behind when it purged the
    // cache and then failed to reach storage, and that has to stay retryable.
    return !superseded
}

/// Get a private key.
/// Will try to get from in-memory dictionary, if not found will try to recreate from data in Keychain.
///  - Parameters:
///      - keyName: Name of the key to retrieve.
///      - generation: Non-nil means the key is being handed to a handle: a hold is taken on the
///        cached entry and the generation it was taken on is reported here. Taken inside the
///        lookup so a concurrent close cannot evict the entry in between.
/// - Returns: Private key, or nil if not found.
private func getKey(
    _ keyName: String, generation: UnsafeMutablePointer<UInt64>?
) -> KeyLookupResult {
    do {
        // Try first from dictionary.
        if let result = getKeyFromDict(keyName: keyName, generation: generation) {
            return .found(result)
        }

        // Try from keychain.
        logDebug("Key not found in dictionary, trying to get from Keychain.")
        switch retrieveDataFromKeychain(account: keyChainAccountName, service: keyName) {
        case .found(let keyChainData):
            let result = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: keyChainData)
            storeKeyInDict(
                keyName: keyName, key: result, generation: generation)
            return .found(result)
        case .notFound:
            logDebug("Key not found in Keychain.")
            return .notFound
        case .failure:
            return .failure
        }
    } catch {
        setError("Error trying to get key: \(error)")
        return .failure
    }
}

/// Store data in the keychain.
/// - Parameters:
///     - data: The data to store.
///     - account: The account name under which the data will be stored.
///     - service: The service name under which the data will be stored.
/// - Returns: OSStatus that indicates the result of the operation.
private func storeDataInKeychain(data: Data, account: String, service: String) -> OSStatus {
    // Define the Keychain query dictionary.
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecValueData as String: data,
    ]

    // No pre-delete: SecItemAdd's errSecDuplicateItem is the reservation. Clearing the way first
    // would overwrite whatever already holds the name, and creation has already refused a name that
    // exists, so a duplicate here means another writer took it after that check.
    let status = SecItemAdd(query as CFDictionary, nil)
    if status == errSecSuccess {
        logTrace("Added item to Keychain.")
    } else if status == errSecDuplicateItem {
        // The caller reports the status; this only records what it means.
        logDebug("Item already exists in Keychain; refusing to replace it.")
    } else {
        // Some other error occurred.
        logDebug("Error adding item to Keychain: \(status)")
    }

    return status
}

/// Count the items stored under this account and service.
/// The legacy Keychain rejects kSecMatchLimitAll combined with kSecReturnData (errSecParam), so
/// ambiguity is detected with a separate attributes-only query before the data is fetched.
/// - Returns: The number of matching items, or nil if the Keychain could not be read.
private func countItemsInKeychain(account: String, service: String) -> Int? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecReturnAttributes as String: kCFBooleanTrue as Any,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]

    var items: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &items)
    if status == errSecItemNotFound {
        return 0
    }
    if status != errSecSuccess {
        logDebug("Error counting items in Keychain: \(status)")
        setError("Error counting items in Keychain: \(status)")
        return nil
    }

    return (items as? [Any])?.count ?? 0
}

/// Retrieve the single item stored under this account and service.
/// - Parameters:
///     - account: The account name under which the data can be found.
///     - service: The service name under which the data can be found.
/// - Returns: The data, .notFound when nothing is stored, or .failure when the Keychain could not
/// be read or more than one item shares the name.
private func retrieveDataFromKeychain(account: String, service: String) -> KeychainDataResult {
    // A name held by more than one item is refused rather than resolved to whichever item the
    // Keychain happens to return first.
    guard let count = countItemsInKeychain(account: account, service: service) else {
        return .failure
    }
    if count == 0 {
        logTrace("Item not found in Keychain.")
        return .notFound
    }
    if count > 1 {
        setError("Refusing to open key: \(count) items share this name.")
        logWarning("Multiple items share the same name; refusing to open an ambiguous key.")
        return .failure
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,

        // We want the data itself returned.
        kSecReturnData as String: kCFBooleanTrue as Any,

        // Exactly one item matched above, so this resolves that item.
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecSuccess {
        logTrace("Retrieved item from Keychain.")
    } else if status == errSecItemNotFound {
        // Item not found.
        logTrace("Item not found in Keychain.")
        return .notFound
    } else {
        // Some other error occurred.
        logDebug("Error retrieving item from Keychain: \(status)")
        setError("Error retrieving item from Keychain: \(status)")
        return .failure
    }

    guard let retrievedData = item as? Data else {
        setError("Keychain returned invalid key data.")
        return .failure
    }

    return .found(retrievedData)
}

/// Remove every item stored under this account and service.
/// A single SecItemDelete removes only one matching item per call, so deleting a name that matches
/// several items one call at a time would report success while leaving the rest in place. A
/// survivor would then resolve unambiguously on the next open, which is exactly the substitution
/// that refusing an ambiguous name exists to prevent. Items are removed until none are left.
/// - Parameters:
///     - account: The account name under which the data can be found.
///     - service: The service name under which the data can be found.
/// - Returns: errSecSuccess if anything was deleted, errSecItemNotFound if there was nothing to
/// delete, otherwise the failing status.
private func removeDataFromKeyChain(account: String, service: String) -> OSStatus {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
    ]

    // A name matches one item per keychain in the search list, so it should never come anywhere
    // near this many. The bound only stops a Keychain that reports success without removing
    // anything from spinning here; reaching it means the loop is not making progress.
    let maxItemsPerName = 1024
    var deleted = 0

    while deleted < maxItemsPerName {
        if SecItemDelete(query as CFDictionary) != errSecSuccess {
            break
        }
        deleted += 1
    }

    // The terminal status is not a reliable signal: measured on macOS, deleting the last item of a
    // multi-keychain match leaves the next call answering errSecInvalidItemRef rather than
    // errSecItemNotFound. What the caller needs to know is whether the name still holds anything,
    // so that is read back rather than inferred.
    guard let remaining = countItemsInKeychain(account: account, service: service) else {
        return errSecInternalError
    }

    if remaining > 0 {
        logDebug("Keychain still holds \(remaining) item(s) named '\(service)' after deleting.")
        setError("Could not delete every item named '\(service)': \(remaining) remain.")
        return errSecInternalError
    }

    if deleted > 0 {
        logTrace("Deleted \(deleted) item(s) from Keychain.")
        return errSecSuccess
    }

    // Item not found, nothing to delete.
    logTrace("Item not found in Keychain, nothing to delete.")
    return errSecItemNotFound
}

/// Get a full key name from a user key name.
/// The full key name includes a prefix for MPSS.
/// - Parameters:
///     - keyName: The user provided key name.
/// - Returns: The key name including the MPSS prefix.
private func getKeyName(_ keyName: String) -> String {
    let result = "com.microsoft.mpss.\(keyName)"
    return result
}

/// Create a random P256 private key in the Secure Enclave.
/// - Parameters:
///     - keyName: Name that identifies the private key.
///     - requireUserPresence: Whether signing requires system user authentication.
/// - Returns: Random private key, or nil if it could not be created.
private func createKeyPriv(
    _ keyName: String, requireUserPresence: Bool, generation: UnsafeMutablePointer<UInt64>
) -> SecureEnclave.P256.Signing.PrivateKey? {
    do {
        let accessFlags: SecAccessControlCreateFlags =
            requireUserPresence ? [.privateKeyUsage, .userPresence] : []

        // Configure Keychain access requirements.
        guard
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                accessFlags,
                nil
            )
        else {
            setError("Unable to create SecAccessControl.")
            return nil
        }

        // Does not exist, create it.
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)

        // Save it now.
        let status = storeDataInKeychain(
            data: privateKey.dataRepresentation, account: keyChainAccountName, service: keyName)

        if status != errSecSuccess {
            setError("Error storing private key in Keychain: \(status)")
            return nil
        }

        storeKeyInDict(keyName: keyName, key: privateKey, generation: generation)

        return privateKey
    } catch {
        setError("Error creating key: '\(error)'")
        return nil
    }
}

/// Whether a secure enclave is available.
/// - Returns: True if the secure enclave is available, false otherwise.
@_cdecl("MPSS_SE_SecureEnclaveIsSupported")
func isSupported() -> Bool {
    clearError()
    #if targetEnvironment(simulator)
    return false
    #else
    return SecureEnclave.isAvailable
    #endif
}

/// Open an existing private key.
/// - Parameters:
///     - keyName: Name of the private key to open.
///     - generation: Receives the generation the hold was taken on. The handle keeps it and
///       presents it with every operation it makes, the release that gives the hold back included.
/// - Returns: Success, expected-negative if absent, or operational-error.
@_cdecl("MPSS_SE_OpenExistingKey")
func openExistingKey(_ keyName: UnsafePointer<CChar>, _ generation: UnsafeMutablePointer<UInt64>)
    -> Int32
{
    clearError()
    let keyNameString = String(cString: keyName)
    return openExistingKey(keyNameString, generation).rawValue
}

/// Open an existing private key.
/// - Parameters:
///     - keyName: Name of the private key to open.
///     - generation: Receives the cache entry the hold was taken on.
/// - Returns: Success, expected-negative if absent, or operational-error.
private func openExistingKey(_ keyName: String, _ generation: UnsafeMutablePointer<UInt64>)
    -> AppleOperationResult
{
    let fullKeyName = getKeyName(keyName)
    switch getKey(fullKeyName, generation: generation) {
    case .found:
        return .success
    case .notFound:
        return .expectedNegative
    case .failure:
        return .operationalError
    }
}

/// Remove existing key.
/// Will remove existing key from the in-memory dictionary and its representation from Keychain.
/// - Parameters:
///     - keyName: Name of the key to remove.
/// - Returns: True if the key was removed successfully, false otherwise.
@_cdecl("MPSS_SE_RemoveExistingKey")
func removeExistingKey(_ keyName: UnsafePointer<CChar>) -> Bool {
    clearError()
    let keyNameString = String(cString: keyName)
    return removeExistingKey(keyNameString)
}

/// Remove existing key.
/// Will remove existing key from the in-memory dictionary and its representation from Keychain.
/// - Parameters:
///     - keyName: Name of the key to remove.
/// - Returns: True if the key was removed successfully, false otherwise.
private func removeExistingKey(_ keyName: String) -> Bool {
    let fullKeyName = getKeyName(keyName)
    purgeKeyFromDict(fullKeyName)
    let status = removeDataFromKeyChain(account: keyChainAccountName, service: fullKeyName)
    return status == errSecSuccess || status == errSecItemNotFound
}

/// Close existing key.
/// Will remove existing key from the in-memory dictionary.
@_cdecl("MPSS_SE_CloseKey")
func closeKey(_ keyName: UnsafePointer<CChar>, _ generation: UInt64) {
    let keyNameString = String(cString: keyName)
    let fullKeyName = getKeyName(keyNameString)
    removeKeyFromDict(fullKeyName, generation)
}

/// Create a random P256 private key in the Secure Enclave.
/// - Parameters:
///     - keyName: Name that identifies the created key.
///     - requireUserPresence: Whether signing requires system user authentication.
/// - Returns: True if key was created successfully, False otherwise.
@_cdecl("MPSS_SE_CreateKey")
func createKey(
    _ keyName: UnsafePointer<CChar>, _ requireUserPresence: Bool,
    _ generation: UnsafeMutablePointer<UInt64>
) -> Bool {
    clearError()
    let keyNameString = String(cString: keyName)
    return createKey(
        keyNameString, requireUserPresence: requireUserPresence, generation: generation)
}

/// Create a random P256 private key in the Secure Enclave.
/// - Parameters:
///     - keyName: Name that identifies the created key.
///     - requireUserPresence: Whether signing requires system user authentication.
/// - Returns: True if key was created successfully, False otherwise.
private func createKey(
    _ keyName: String, requireUserPresence: Bool, generation: UnsafeMutablePointer<UInt64>
) -> Bool {
    let fullKeyName = getKeyName(keyName)
    let privateKey = createKeyPriv(
        fullKeyName, requireUserPresence: requireUserPresence, generation: generation)
    if nil == privateKey {
        return false
    }
    return true
}

/// Sign a hash with the given private key.
/// - Parameters:
///     - keyName: Name that identifies the private key to use.
///     - hash: Buffer that contains the hash to sign.
///     - hashLength: Size of the hash buffer.
///     - sig: Buffer that will receive the signature.
///     - sigLength: Size of the signature buffer. Will be updated with the number of bytes written to the signature buffer.
/// - Returns: True if the signature was created successfully, False otherwise.
@_cdecl("MPSS_SE_Sign")
func sign(
    _ keyName: UnsafePointer<CChar>, hash: UnsafePointer<UInt8>, hashLength: UInt,
    sig: UnsafeMutablePointer<UInt8>, sigLength: UnsafeMutablePointer<UInt>, generation: UInt64
) -> Bool {
    clearError()
    let keyNameString = String(cString: keyName)
    let hashData = Data(bytes: hash, count: Int(hashLength))

    guard let hashDigest = SHA256Digest.fromData(hashData) else {
        setError("Invalid hash size: \(hashData.count) (expected \(SHA256Digest.byteCount))")
        return false
    }

    guard let signature = sign(keyName: keyNameString, hash: hashDigest, generation: generation)
    else {
        return false
    }

    if signature.count > Int(sigLength.pointee) {
        // Not enough space in buffer.
        setError(
            "Not enough space in signature buffer: \(sigLength.pointee) (expected \(signature.count))"
        )
        return false
    }

    sigLength.pointee = UInt(signature.count)
    signature.copyBytes(to: sig, count: signature.count)

    return true
}

/// Sign a hash with the given private key.
/// - Parameters:
///     - keyName: Name that identifies the private key to use.
///     - hash: The hash to sign.
/// - Returns: Data that contains the signature, or nil if failed to sign.
private func sign(keyName: String, hash: any Digest, generation: UInt64) -> Data? {
    do {
        let fullKeyName = getKeyName(keyName)

        guard let privateKey = getKeyForGeneration(fullKeyName, generation) else {
            setError("Key '\(keyName)' is no longer the key this handle opened.")
            return nil
        }

        let signature = try privateKey.signature(for: hash)

        return signature.derRepresentation
    } catch {
        setError("Error trying to sign hash: \(error)")
        return nil
    }
}

/// Verify the given signature of the given hash using the given private key.
/// - Parameters:
///     - keyName: Name of the key to use for verification.
///     - hash: Buffer with the hash to verify.
///     - hashLength: Size of the hash buffer.
///     - signature: Buffer with the signature to verify.
///     - signatureLength: Size of the signature buffer.
/// - Returns: Success, expected-negative if invalid, or operational-error.
@_cdecl("MPSS_SE_VerifySignature")
func verifySignature(
    keyName: UnsafePointer<CChar>, hash: UnsafePointer<UInt8>, hashLength: UInt,
    signature: UnsafePointer<UInt8>, signatureLength: UInt, generation: UInt64
) -> Int32 {
    clearError()
    let keyNameString = String(cString: keyName)
    let hashData = Data(bytes: hash, count: Int(hashLength))
    let signatureData = Data(bytes: signature, count: Int(signatureLength))

    guard let hashDigest = SHA256Digest.fromData(hashData) else {
        setError("Invalid hash size: \(hashData.count) (expected \(SHA256Digest.byteCount))")
        return AppleOperationResult.operationalError.rawValue
    }

    return verifySignature(
        keyName: keyNameString, hash: hashDigest, signature: signatureData,
        generation: generation
    ).rawValue
}

/// Verify the given signature of the given hash using the given private key.
/// - Parameters:
///     - keyName: Name of the key to use for verification.
///     - hash: Hash to verify.
///     - signature: Signature to verify.
/// - Returns: Success, expected-negative if invalid, or operational-error.
private func verifySignature(
    keyName: String, hash: any Digest, signature: Data, generation: UInt64
) -> AppleOperationResult {
    do {
        let fullKeyName = getKeyName(keyName)

        guard let privateKey = getKeyForGeneration(fullKeyName, generation) else {
            setError("Key '\(keyName)' is no longer the key this handle opened.")
            return .operationalError
        }

        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        return privateKey.publicKey.isValidSignature(ecdsaSignature, for: hash)
            ? .success : .expectedNegative
    } catch {
        setError("Error verifying signature: \(error)")
        return .operationalError
    }
}

/// Verify the given signature of the given hash using the given public key.
/// - Parameters:
///     - pk: Buffer with the public key to use for verification.
///     - pkLength: Size of the public key buffer.
///     - hash: Buffer with the hash to verify.
///     - hashLength: Size of the hash buffer.
///     - signature: Buffer with the signature to verify.
///     - signatureLength: Size of the signature buffer.
/// - Returns: Success, expected-negative if invalid, or operational-error.
@_cdecl("MPSS_SE_VerifyStandaloneSignature")
func verifyStandaloneSignature(
    pk: UnsafePointer<UInt8>, pkLength: UInt, hash: UnsafePointer<UInt8>, hashLength: UInt,
    signature: UnsafePointer<UInt8>, signatureLength: UInt
) -> Int32 {
    clearError()
    let pkData = Data(bytes: pk, count: Int(pkLength))
    let hashData = Data(bytes: hash, count: Int(hashLength))
    let signatureData = Data(bytes: signature, count: Int(signatureLength))

    guard let hashDigest = SHA256Digest.fromData(hashData) else {
        setError("Invalid hash size: \(hashData.count) (expected \(SHA256Digest.byteCount))")
        return AppleOperationResult.operationalError.rawValue
    }

    return verifyStandaloneSignature(
        pk: pkData, hash: hashDigest, signature: signatureData
    ).rawValue
}

/// Verify the given signature of the given hash using the given public key.
/// - Parameters:
///     - pk: Data representation of the public key.
///     - hash: Data of the hash to verify.
///     - signature: Data of the signature to verify.
/// - Returns: Success, expected-negative if invalid, or operational-error.
private func verifyStandaloneSignature(
    pk: Data, hash: any Digest, signature: Data
) -> AppleOperationResult {
    do {
        // Recreate public key.
        let publicKey = try P256.Signing.PublicKey.init(x963Representation: pk)
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)

        return publicKey.isValidSignature(ecdsaSignature, for: hash)
            ? .success : .expectedNegative
    } catch {
        setError("Error verifying signature: \(error)")
        return .operationalError
    }
}

/// Get x9.63 representation of the public key of the given private key.
/// - Parameters:
///     - keyName: Name of the private key.
///     - pk: Buffer that will receive the public key representation.
///     - pkLength: Size of the public key buffer. Will be updated with the bytes written to the buffer.
/// - Returns: True if the public key representation was obtained successfully, False otherwise.
@_cdecl("MPSS_SE_GetPublicKey")
func getPublicKey(
    keyName: UnsafePointer<CChar>, pk: UnsafeMutablePointer<UInt8>,
    pkLength: UnsafeMutablePointer<UInt>, generation: UInt64
) -> Bool {
    clearError()
    let keyNameString = String(cString: keyName)

    guard let publicKey = getPublicKey(keyName: keyNameString, generation: generation) else {
        return false
    }

    if publicKey.count > pkLength.pointee {
        // Not enough space.
        setError(
            "Not enough space to store public key. Got: \(pkLength.pointee), needed: \(publicKey.count)"
        )
        return false
    }

    publicKey.copyBytes(to: pk, count: publicKey.count)
    pkLength.pointee = UInt(publicKey.count)

    return true
}

/// Get x9.63 representation of the public key of the given private key.
/// - Parameters:
///     - keyName: Name of the private key.
/// - Returns: x9.63 representation of the public key, nil if not able to get representation.
private func getPublicKey(keyName: String, generation: UInt64) -> Data? {
    let fullKeyName = getKeyName(keyName)

    guard let privateKey = getKeyForGeneration(fullKeyName, generation) else {
        setError("Key '\(keyName)' is no longer the key this handle opened.")
        return nil
    }

    let publicKey = privateKey.publicKey
    return publicKey.x963Representation
}

/// Get last error.
/// - Parameters:
///     - error: Buffer where last error will be written.
///     - errorLength: Size of the error buffer.
/// - Returns: If error is nil: Size of the buffer needed to write the last error. If error is not nil, bytes written to error buffer. If not enough space to write error, will return 0.
@_cdecl("MPSS_SE_GetLastError")
func getLastError(error: UnsafeMutablePointer<CChar>?, errorLength: UInt) -> UInt {
    let lastError = getError()
    let utf8 = Array(lastError.utf8)

    // Return string size if error is nil.
    if error == nil {
        return UInt(utf8.count)
    }

    if utf8.count > Int(errorLength) {
        // Not enough space.
        return 0
    }

    utf8.withUnsafeBytes { bytes in
        if let baseAddress = bytes.baseAddress {
            memcpy(error!, baseAddress, utf8.count)
        }
    }

    clearError()
    return UInt(utf8.count)
}
