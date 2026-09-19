// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <TargetConditionals.h>

#include "mpss/impl/apple/apple_result.h"
#include "mpss/log_c.h"

// Global dictionary to store SecKeyRef instances.
static dispatch_queue_t _keyStoreQueue;                 // NOLINT(bugprone-reserved-identifier)
static NSMutableDictionary<NSString *, id> *_keyStore;  // NOLINT(bugprone-reserved-identifier)

// How many open handles depend on each cached key, so that one handle's close does not evict an
// entry another handle is still using.
static NSMutableDictionary<NSString *, NSNumber *> *_keyStoreRefs;  // NOLINT(bugprone-reserved-identifier)

// Which entry each hold was taken on. A name can be deleted and created again while a handle to the
// old key is still alive, and that handle's release must not be charged against the new key. Holds
// therefore name a generation, and a release for a generation the cache has moved past does
// nothing. Generations are never reused.
static NSMutableDictionary<NSString *, NSNumber *> *_keyStoreGen;  // NOLINT(bugprone-reserved-identifier)
static uint64_t _nextGeneration;                                   // NOLINT(bugprone-reserved-identifier)

void InitializeKeyStore() {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    _keyStoreQueue = dispatch_queue_create("com.microsoft.mpss.KeyStore", DISPATCH_QUEUE_SERIAL);
    _keyStore = [[NSMutableDictionary alloc] init];
    _keyStoreRefs = [[NSMutableDictionary alloc] init];
    _keyStoreGen = [[NSMutableDictionary alloc] init];
  });
}

void SetThreadLocalError(NSString *error) {
  [[NSThread currentThread].threadDictionary setObject:error forKey:@"MyThreadLocalError"];
}

NSString *GetThreadLocalError() {
  return [[NSThread currentThread].threadDictionary objectForKey:@"MyThreadLocalError"];
}

void ClearThreadLocalError() {
  [[NSThread currentThread].threadDictionary removeObjectForKey:@"MyThreadLocalError"];
}

NSString *GetKeyLabel(const char *keyName) {
  NSString *keyLabel = [NSString stringWithUTF8String:keyName];
  NSString *keyNameWithPrefix = [NSString stringWithFormat:@"com.microsoft.mpss.%@", keyLabel];
  return keyNameWithPrefix;
}

// Taking the hold inside the block that finds or stores the entry keeps a concurrent close or
// delete from evicting it in between, which would leave a hold recorded against a name with
// nothing cached.
static uint64_t RetainLocked(NSString *keyLabel) {
  NSNumber *holds = _keyStoreRefs[keyLabel];
  _keyStoreRefs[keyLabel] = @((holds != nil ? [holds integerValue] : 0) + 1);
  return [_keyStoreGen[keyLabel] unsignedLongLongValue];
}

void StoreKey(NSString *keyLabel, SecKeyRef keyRef, BOOL takeHold, uint64_t *generation) {
  InitializeKeyStore();

  if (keyLabel && keyRef) {
    dispatch_sync(_keyStoreQueue, ^{
      _keyStore[keyLabel] = (__bridge id)keyRef;
      // A generation is established when the name starts being cached and kept while it stays
      // cached, so that two lookups which both miss and both store do not orphan the first one's
      // hold. Deleting removes the generation, which is what makes the next create a new one.
      if (_keyStoreGen[keyLabel] == nil) {
        _keyStoreGen[keyLabel] = @(++_nextGeneration);
      }
      const uint64_t taken = takeHold ? RetainLocked(keyLabel) : 0;
      if (generation != NULL) {
        *generation = taken;
      }
    });
  }
}

SecKeyRef CopyKey(NSString *keyLabel, BOOL takeHold, uint64_t *generation) {
  InitializeKeyStore();

  __block SecKeyRef result = NULL;
  dispatch_sync(_keyStoreQueue, ^{
    result = (__bridge SecKeyRef)(_keyStore[keyLabel]);
    if (result) {
      CFRetain(result);
      const uint64_t taken = takeHold ? RetainLocked(keyLabel) : 0;
      if (generation != NULL) {
        *generation = taken;
      }
    }
  });
  return result;
}

void RemoveKey(NSString *keyLabel, uint64_t generation) {
  InitializeKeyStore();

  dispatch_sync(_keyStoreQueue, ^{
    NSNumber *current = _keyStoreGen[keyLabel];
    if (current == nil || [current unsignedLongLongValue] != generation) {
      // The hold was taken on an entry this name has since moved past, so there is nothing of this
      // handle's left to give up and the entry now under the name belongs to someone else.
      return;
    }
    NSNumber *holds = _keyStoreRefs[keyLabel];
    if (holds != nil && [holds integerValue] > 1) {
      _keyStoreRefs[keyLabel] = @([holds integerValue] - 1);
      return;
    }
    [_keyStoreRefs removeObjectForKey:keyLabel];
    [_keyStoreGen removeObjectForKey:keyLabel];
    [_keyStore removeObjectForKey:keyLabel];
  });
}

// Drop a cached key regardless of how many holds remain. Deleting a key invalidates every handle
// to it, so the entry must not survive on another handle's hold.
void PurgeKey(NSString *keyLabel) {
  InitializeKeyStore();

  dispatch_sync(_keyStoreQueue, ^{
    [_keyStoreRefs removeObjectForKey:keyLabel];
    [_keyStoreGen removeObjectForKey:keyLabel];
    [_keyStore removeObjectForKey:keyLabel];
  });
}

int GetKeySize(SecKeyRef keyRef) {
  // Retrieve the key size.
  CFDictionaryRef attrs = SecKeyCopyAttributes(keyRef);
  NSNumber *keySizeNumber = (__bridge NSNumber *)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
  int bitSize = [keySizeNumber intValue];
  CFRelease(attrs);

  return bitSize;
}

SecKeyAlgorithm GetAlgorithm(int signatureType) {
  switch (signatureType) {
    case 1:  // ECDSA SHA 256
      return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    case 2:  // ECDSA SHA 384
      return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
    case 3:  // ECDSA SHA 512
      return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
    default:
      mpss_log_warning("Unsupported signature type.");
      return NULL;
  }
}

int GetKeyBitSize(int signatureType) {
  switch (signatureType) {
    case 1:  // ECDSA SHA 256
      return 256;
    case 2:  // ECDSA SHA 384
      return 384;
    case 3:  // ECDSA SHA 512
      return 521;
    default:
      mpss_log_warning("Unsupported signature type.");
      return -1;
  }
}

// The Keychain key type every MPSS-created key uses on this platform. Centralized so the create,
// open, and delete match filters stay in lockstep: the open/delete filters accept exactly what
// create produces. Adding a non-EC scheme is a single-point change here (the open query would then
// need to match a set of types rather than one).
static id SupportedKeychainKeyType() {
  return (id)kSecAttrKeyTypeECSECPrimeRandom;
}

static bool IsExpectedVerificationFailure(CFErrorRef error) {
  return error != NULL && CFEqual(CFErrorGetDomain(error), kCFErrorDomainOSStatus) &&
         CFErrorGetCode(error) == errSecVerifyFailed;
}

static int32_t OpenExistingKeyInternal(NSString *keyLabel, int *bitSize, BOOL takeHold, uint64_t *generation) {
  SecKeyRef keyRef = CopyKey(keyLabel, takeHold, generation);

  if (keyRef) {
    mpss_log_debug("Found existing key in local dictionary.");
    *bitSize = GetKeySize(keyRef);
    CFRelease(keyRef);
    return MPSS_APPLE_RESULT_SUCCESS;
  }

  mpss_log_debug("Did not find key in local dictionary, querying from OS.");

  // The Keychain does not enforce uniqueness on the application tag for key items (their identity
  // also includes the public-key hash), so items sharing a name can coexist. Match all of them so
  // an ambiguous name can be detected and refused rather than resolving to an arbitrary item.
  NSDictionary *query = @{
    (id)kSecClass : (__bridge id)kSecClassKey,
    (id)kSecAttrKeyType : SupportedKeychainKeyType(),
    (id)kSecAttrApplicationTag : [keyLabel dataUsingEncoding:NSUTF8StringEncoding],
    (id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
    (id)kSecReturnRef : @YES,
    (id)kSecMatchLimit : (__bridge id)kSecMatchLimitAll
  };

  CFTypeRef matches = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &matches);

  if (status == errSecItemNotFound) {
    return MPSS_APPLE_RESULT_EXPECTED_NEGATIVE;
  }

  if (status != errSecSuccess) {
    NSString *error = [NSString stringWithFormat:@"Failed to retrieve key with status: %d", (int)status];
    SetThreadLocalError(error);
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  CFArrayRef items = (CFArrayRef)matches;
  CFIndex count = (items != NULL) ? CFArrayGetCount(items) : 0;

  if (count == 0) {
    if (items != NULL) {
      CFRelease(items);
    }
    return MPSS_APPLE_RESULT_EXPECTED_NEGATIVE;
  }

  if (count > 1) {
    CFRelease(items);
    NSString *error = [NSString stringWithFormat:@"Refusing to open key: %ld items share this name.", (long)count];
    SetThreadLocalError(error);
    mpss_log_warning("Multiple keys share the same name; refusing to open an ambiguous key.");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  // The array holds a strong reference to its elements, so retain before releasing the array to
  // keep the key alive across the handoff.
  keyRef = (SecKeyRef)CFArrayGetValueAtIndex(items, 0);
  CFRetain(keyRef);
  CFRelease(items);

  mpss_log_debug("Retrieved key from OS.");
  StoreKey(keyLabel, keyRef, takeHold, generation);
  *bitSize = GetKeySize(keyRef);
  CFRelease(keyRef);
  return MPSS_APPLE_RESULT_SUCCESS;
}

////////////////////////////////////////////////////////
// From here on below, the public functions.
////////////////////////////////////////////////////////

void MPSS_RemoveKey(const char *keyName, uint64_t generation) {
  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    RemoveKey(keyLabel, generation);
  }
}

int32_t MPSS_OpenExistingKey(const char *keyName, int *bitSize, uint64_t *generation) {
  ClearThreadLocalError();
  if (keyName == NULL || bitSize == NULL || generation == NULL) {
    SetThreadLocalError(@"Invalid parameters (keyName, bitSize or generation is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    return OpenExistingKeyInternal(keyLabel, bitSize, YES, generation);
  }
}

// Counts the private-key items carrying this name. Uses the same query shape as the ambiguity check
// in OpenExistingKeyInternal, but deliberately bypasses the in-process key cache: this runs right
// after a creation, when the cache cannot yet reflect what another process has done.
static OSStatus CountItemsWithName(NSString *keyLabel, CFIndex *countOut) {
  *countOut = 0;

  NSDictionary *query = @{
    (id)kSecClass : (__bridge id)kSecClassKey,
    (id)kSecAttrKeyType : SupportedKeychainKeyType(),
    (id)kSecAttrApplicationTag : [keyLabel dataUsingEncoding:NSUTF8StringEncoding],
    (id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
    (id)kSecReturnRef : @YES,
    (id)kSecMatchLimit : (__bridge id)kSecMatchLimitAll
  };

  CFTypeRef matches = NULL;
  const OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &matches);

  if (status == errSecItemNotFound) {
    return errSecSuccess;
  }
  if (status != errSecSuccess) {
    return status;
  }

  CFArrayRef items = (CFArrayRef)matches;
  if (items != NULL) {
    *countOut = CFArrayGetCount(items);
    CFRelease(items);
  }
  return errSecSuccess;
}

int32_t MPSS_KeychainKeyExists(const char *keyName) {
  ClearThreadLocalError();
  if (keyName == NULL) {
    SetThreadLocalError(@"Invalid parameter (keyName is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    CFIndex count = 0;
    const OSStatus status = CountItemsWithName(keyLabel, &count);
    if (status != errSecSuccess) {
      NSString *error = [NSString stringWithFormat:@"Failed to determine whether the Keychain holds this "
                                                   @"name; status: %d",
                                                   (int)status];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    return (count > 0) ? MPSS_APPLE_RESULT_SUCCESS : MPSS_APPLE_RESULT_EXPECTED_NEGATIVE;
  }
}

bool MPSS_CreateKey(const char *keyName, int bitSize, uint64_t *generation) {
  ClearThreadLocalError();
  if (keyName == NULL) {
    SetThreadLocalError(@"Invalid parameter (keyName is NULL).");
    return false;
  }

  // Define key attributes.
  @autoreleasepool {
    int existingBitSize = 0;
    NSString *keyLabel = GetKeyLabel(keyName);
    const int32_t openResult = OpenExistingKeyInternal(keyLabel, &existingBitSize, NO, NULL);
    if (openResult == MPSS_APPLE_RESULT_SUCCESS) {
      NSString *error = [NSString stringWithFormat:@"Key %s already exists.", keyName];
      SetThreadLocalError(error);
      return false;
    }
    if (openResult == MPSS_APPLE_RESULT_OPERATIONAL_ERROR) {
      return false;
    }
    if (openResult != MPSS_APPLE_RESULT_EXPECTED_NEGATIVE) {
      NSString *error = [NSString stringWithFormat:@"Open returned invalid result: %d", openResult];
      SetThreadLocalError(error);
      return false;
    }

    int keyBitSize = GetKeyBitSize(bitSize);
    mpss_log_debug([[NSString stringWithFormat:@"Key bit size: %d", keyBitSize] UTF8String]);
    if (keyBitSize == -1) {
      NSString *error = [NSString stringWithFormat:@"Unsupported bit size: %d", bitSize];
      SetThreadLocalError(error);
      return false;
    }

    mpss_log_debug([[NSString stringWithFormat:@"Creating key with bit size %d", keyBitSize] UTF8String]);
    NSDictionary *privateKeyAttributes = @{
      (id)kSecAttrIsPermanent : @YES,
      (id)kSecAttrLabel : keyLabel,
      (id)kSecAttrApplicationTag : [keyLabel dataUsingEncoding:NSUTF8StringEncoding],
      (id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    };
#if TARGET_OS_OSX
    SecAccessRef keyAccess = NULL;

    // SecAccess is the only macOS API that names legacy Keychain items in authorization dialogs.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    const OSStatus accessStatus = SecAccessCreate((__bridge CFStringRef)keyLabel, NULL, &keyAccess);
#pragma clang diagnostic pop

    if (accessStatus != errSecSuccess) {
      NSString *error =
          [NSString stringWithFormat:@"Failed to create key access controls with status: %d", (int)accessStatus];
      SetThreadLocalError(error);
      return false;
    }

#endif
    NSMutableDictionary *keyAttributes = [NSMutableDictionary dictionaryWithDictionary:@{
      (id)kSecAttrKeyType : SupportedKeychainKeyType(),
      (id)kSecAttrKeySizeInBits : @(keyBitSize),  // NOLINT(readability-redundant-parentheses)
      (id)kSecPrivateKeyAttrs : privateKeyAttributes
    }];
#if TARGET_OS_OSX
    keyAttributes[(id)kSecAttrAccess] = (__bridge id)keyAccess;
#endif

    // Generate the key.
    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, &error);
#if TARGET_OS_OSX
    CFRelease(keyAccess);
#endif

    if (keyRef == NULL) {
      NSError *err = CFBridgingRelease(error);
      NSString *error = [NSString stringWithFormat:@"Failed to generate key: %@", err];
      SetThreadLocalError(error);
      return false;
    }

    mpss_log_trace("Key generated successfully.");

    // The existence check at the top of this function and the creation above are not atomic, and the
    // Keychain does not enforce uniqueness on the application tag, so a concurrent creator can add a
    // second item under this name in between. Confirm the name resolves to exactly one item and, if
    // it does not, remove the item just created and report failure. Deleting by reference bounds the
    // removal to this key, so a concurrent creator's key is never touched.
    CFIndex matchCount = 0;
    const OSStatus countStatus = CountItemsWithName(keyLabel, &matchCount);
    if (countStatus != errSecSuccess || matchCount != 1) {
      NSDictionary *deleteQuery = @{(id)kSecClass : (__bridge id)kSecClassKey, (id)kSecValueRef : (__bridge id)keyRef};
      const OSStatus deleteStatus = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
      CFRelease(keyRef);

      if (countStatus != errSecSuccess) {
        SetThreadLocalError(
            [NSString stringWithFormat:@"Could not confirm key '%s' is unique after creation, status: %d.", keyName,
                                       (int)countStatus]);
      } else {
        SetThreadLocalError([NSString stringWithFormat:@"Refusing to create key '%s': %ld items share "
                                                       @"this name after creation.",
                                                       keyName, (long)matchCount]);
      }

      if (deleteStatus != errSecSuccess) {
        mpss_log_warning("Failed to remove the key created under a name that is not unique.");
      }
      return false;
    }

    StoreKey(keyLabel, keyRef, YES, generation);
    CFRelease(keyRef);

    return true;
  }
}

bool MPSS_SignHash(const char *keyName, int signatureType, const uint8_t *hash, size_t hashSize, uint8_t *signature,
                   size_t *signatureSize) {
  ClearThreadLocalError();
  if (keyName == NULL || hash == NULL || signature == NULL || signatureSize == NULL) {
    SetThreadLocalError(@"Invalid parameters (keyName, hash, signature, or signatureSize is NULL).");
    return false;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    SecKeyRef keyRef = CopyKey(keyLabel, NO, NULL);

    if (keyRef == NULL) {
      mpss_log_debug("Key not found.");
      SetThreadLocalError(@"Key not found.");
      return false;
    }

    NSData *hashData = [NSData dataWithBytes:hash length:hashSize];

    SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
    if (algorithm == NULL) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      CFRelease(keyRef);
      return false;
    }

    CFErrorRef error = NULL;
    CFDataRef signatureData = SecKeyCreateSignature(keyRef, algorithm, (__bridge CFDataRef)hashData, &error);
    CFRelease(keyRef);

    if (signatureData == NULL) {
      NSError *err = CFBridgingRelease(error);
      NSString *error = [NSString stringWithFormat:@"Failed to sign hash: %@", err];
      SetThreadLocalError(error);
      return false;
    }

    size_t signatureDataSize = CFDataGetLength(signatureData);
    if (*signatureSize < signatureDataSize) {
      NSString *error = [NSString stringWithFormat:@"Insufficient buffer provided. Buffer "
                                                   @"size: %lu, signature size: %lu",
                                                   *signatureSize, signatureDataSize];
      SetThreadLocalError(error);
      CFRelease(signatureData);
      return false;
    }

    // Actual signature size.
    *signatureSize = signatureDataSize;

    // Copy signature.
    memcpy(signature, CFDataGetBytePtr(signatureData), signatureDataSize);
    mpss_log_debug([[NSString
        stringWithFormat:@"Signature created successfully. Signature size: %lu", signatureDataSize] UTF8String]);

    CFRelease(signatureData);

    return true;
  }
}

int32_t MPSS_VerifySignature(const char *keyName, int signatureType, const uint8_t *hash, size_t hashSize,
                             const uint8_t *signature, size_t signatureSize) {
  ClearThreadLocalError();
  if (keyName == NULL || hash == NULL || signature == NULL) {
    SetThreadLocalError(@"Invalid parameters (keyName, hash, or signature is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    SecKeyRef keyRef = CopyKey(keyLabel, NO, NULL);

    if (keyRef == NULL) {
      NSString *error = @"Key not found.";
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    NSData *hashData = [NSData dataWithBytes:hash length:hashSize];
    NSData *signatureData = [NSData dataWithBytes:signature length:signatureSize];

    SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
    if (algorithm == NULL) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      CFRelease(keyRef);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    SecKeyRef publicKeyRef = SecKeyCopyPublicKey(keyRef);
    CFRelease(keyRef);
    if (!publicKeyRef) {
      NSString *error = @"Could not copy public key.";
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    CFErrorRef error = NULL;
    bool result = SecKeyVerifySignature(publicKeyRef, algorithm, (__bridge CFDataRef)hashData,
                                        (__bridge CFDataRef)signatureData, &error);

    // Release public key.
    CFRelease(publicKeyRef);

    if (result) {
      if (error != NULL) {
        CFRelease(error);
      }
      return MPSS_APPLE_RESULT_SUCCESS;
    }

    const bool expectedNegative = IsExpectedVerificationFailure(error);
    if (!expectedNegative) {
      NSString *detail = error == NULL ? @"No platform error detail." : [(__bridge NSError *)error description];
      NSString *errorMessage = [NSString stringWithFormat:@"Failed to verify signature: %@", detail];
      SetThreadLocalError(errorMessage);
    }
    if (error != NULL) {
      CFRelease(error);
    }
    return expectedNegative ? MPSS_APPLE_RESULT_EXPECTED_NEGATIVE : MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }
}

int32_t MPSS_VerifyStandaloneSignature(int signatureType, const uint8_t *hash, size_t hashSize,
                                       const uint8_t *publicKey, size_t publicKeySize, const uint8_t *signature,
                                       size_t signatureSize) {
  ClearThreadLocalError();
  if (hash == NULL || publicKey == NULL || signature == NULL) {
    SetThreadLocalError(@"Invalid parameters (hash, publicKey, or signature is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSData *hashData = [NSData dataWithBytes:hash length:hashSize];
    NSData *signatureData = [NSData dataWithBytes:signature length:signatureSize];
    NSData *publicKeyData = [NSData dataWithBytes:publicKey length:publicKeySize];

    SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
    mpss_log_debug([[NSString stringWithFormat:@"Algorithm: %@", algorithm] UTF8String]);
    if (algorithm == NULL) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    int keyBitSize = GetKeyBitSize(signatureType);
    mpss_log_debug([[NSString stringWithFormat:@"Key bit size: %d", keyBitSize] UTF8String]);

    if (keyBitSize == -1) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    // Create public key attributes.
    NSDictionary *keyAttributes = @{
      (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
      (id)kSecAttrKeyClass : (id)kSecAttrKeyClassPublic,
      (id)kSecAttrKeySizeInBits : @(keyBitSize),  // NOLINT(readability-redundant-parentheses)
      (id)kSecAttrIsPermanent : @NO
    };

    // Create public key from raw bytes.
    CFErrorRef error = NULL;
    SecKeyRef publicKeyRef =
        SecKeyCreateWithData((__bridge CFDataRef)publicKeyData, (__bridge CFDictionaryRef)keyAttributes, &error);

    if (!publicKeyRef) {
      NSError *err = CFBridgingRelease(error);
      NSString *error = [NSString stringWithFormat:@"Failed to create public key from data: %@", err];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    // Verify the signature.
    bool result = SecKeyVerifySignature(publicKeyRef, algorithm, (__bridge CFDataRef)hashData,
                                        (__bridge CFDataRef)signatureData, &error);

    // Release public key.
    CFRelease(publicKeyRef);

    if (result) {
      if (error != NULL) {
        CFRelease(error);
      }
      return MPSS_APPLE_RESULT_SUCCESS;
    }

    const bool expectedNegative = IsExpectedVerificationFailure(error);
    if (!expectedNegative) {
      NSString *detail = error == NULL ? @"No platform error detail." : [(__bridge NSError *)error description];
      NSString *errorMessage = [NSString stringWithFormat:@"Failed to verify standalone signature: %@", detail];
      SetThreadLocalError(errorMessage);
    }
    if (error != NULL) {
      CFRelease(error);
    }
    return expectedNegative ? MPSS_APPLE_RESULT_EXPECTED_NEGATIVE : MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }
}

bool MPSS_GetPublicKey(const char *keyName, uint8_t *pk, size_t *pkSize) {
  ClearThreadLocalError();
  if (NULL == keyName || NULL == pk || NULL == pkSize) {
    SetThreadLocalError(@"Invalid parameters (keyName, pk, or pkSize is NULL).");
    return false;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    SecKeyRef keyRef = CopyKey(keyLabel, NO, NULL);

    if (keyRef == NULL) {
      NSString *error = @"Key not found.";
      SetThreadLocalError(error);
      return false;
    }

    SecKeyRef publicKeyRef = SecKeyCopyPublicKey(keyRef);
    CFRelease(keyRef);
    if (publicKeyRef == NULL) {
      NSString *error = @"Could not copy public key.";
      SetThreadLocalError(error);
      return false;
    }

    // Get PK data.
    CFErrorRef error = NULL;
    CFDataRef pkData = SecKeyCopyExternalRepresentation(publicKeyRef, &error);

    if (!pkData) {
      NSError *err = CFBridgingRelease(error);
      NSString *errStr = [NSString stringWithFormat:@"Failed to copy public key external representation: %@", err];
      SetThreadLocalError(errStr);
      CFRelease(publicKeyRef);
      return false;
    }

    // Get raw bytes.
    CFIndex length = CFDataGetLength(pkData);
    const UInt8 *pkBytes = CFDataGetBytePtr(pkData);

    if (*pkSize < length) {
      NSString *errStr =
          [NSString stringWithFormat:@"Insufficient buffer. Provided: %lu, needed: %lu", *pkSize, length];
      SetThreadLocalError(errStr);
      CFRelease(pkData);
      CFRelease(publicKeyRef);
      return false;
    }

    memcpy(pk, pkBytes, length);
    // Actual size.
    *pkSize = length;

    CFRelease(pkData);
    CFRelease(publicKeyRef);

    return true;
  }
}

// Deletes every Keychain item matching the query, reporting how many were removed.
//
// A single SecItemDelete removes only one matching item per call, so deleting a name that matches
// several items one call at a time would report success while leaving the rest in place. Items are
// removed until the Keychain reports there are none left.
static OSStatus DeleteAllMatchingItems(NSDictionary *query, NSUInteger *deletedCount) {
  // A name matches one item per distinct key, so it should never come anywhere near this many. The
  // bound exists only so that a Keychain reporting success without removing anything cannot spin
  // here forever; reaching it means the loop is not making progress.
  static const NSUInteger maxItemsPerName = 1024;

  NSUInteger deleted = 0;
  while (deleted < maxItemsPerName) {
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status == errSecItemNotFound) {
      *deletedCount = deleted;
      return deleted > 0 ? errSecSuccess : errSecItemNotFound;
    }
    if (status != errSecSuccess) {
      *deletedCount = deleted;
      return status;
    }
    deleted++;
  }

  *deletedCount = deleted;
  return errSecInternalError;
}

bool MPSS_DeleteKey(const char *keyName) {
  ClearThreadLocalError();
  if (keyName == NULL) {
    SetThreadLocalError(@"Invalid parameter (keyName is NULL).");
    return false;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    PurgeKey(keyLabel);

    NSString *op_status = @"";

    // Create query to delete private key.
    NSMutableDictionary *query = [@{
      (id)kSecClass : (__bridge id)kSecClassKey,
      (id)kSecAttrKeyType : SupportedKeychainKeyType(),
      (id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
      (id)kSecAttrApplicationTag : [keyLabel dataUsingEncoding:NSUTF8StringEncoding]
    } mutableCopy];

    NSUInteger deleted = 0;
    OSStatus status = DeleteAllMatchingItems(query, &deleted);

    if (status == errSecSuccess) {
      mpss_log_trace(
          [[NSString stringWithFormat:@"Deleted %lu private key item(s).", (unsigned long)deleted] UTF8String]);
    } else if (status == errSecItemNotFound) {
      mpss_log_trace("Private key not found, nothing to delete.");
    } else {
      // Append to status.
      op_status = [op_status stringByAppendingFormat:@"Private key deletion failed with status: %d", (int)status];
    }

    // Nothing this library creates matches here: SecKeyCreateRandomKey stores only the private key,
    // and the public half is derived on demand rather than persisted. The pass is kept for keys left
    // by the deprecated SecKeyGeneratePair, which stored both halves as separate items, so an older
    // build or another tool can leave a public key behind. Matching nothing is a success. This is
    // transitional: remove the pass once those legacy keys are no longer supported.
    query[(id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPublic;

    status = DeleteAllMatchingItems(query, &deleted);

    if (status == errSecSuccess) {
      mpss_log_trace(
          [[NSString stringWithFormat:@"Deleted %lu public key item(s).", (unsigned long)deleted] UTF8String]);
    } else if (status == errSecItemNotFound) {
      mpss_log_trace("Public key not found, nothing to delete.");
    } else {
      // Append to status.
      op_status = [op_status stringByAppendingFormat:@"Public key deletion failed with status: %d", (int)status];
    }

    if ([op_status length] > 0) {
      SetThreadLocalError(op_status);
      return false;
    }

    return true;
  }
}

size_t MPSS_GetLastError(char *error, size_t errorSize) {
  @autoreleasepool {
    NSString *lastError = GetThreadLocalError() ?: @"";
    const char *utf8 = [lastError UTF8String];
    size_t need = strlen(utf8);
    if (error == NULL) {
      // Size query: report the needed length without consuming the error.
      return need;
    }
    if (errorSize < need) {
      return 0;
    }
    // Copy while the autorelease pool (and thus utf8) is still alive.
    memcpy(error, utf8, need);
    // Clear on read so a later failure that sets no error cannot surface this stale one.
    ClearThreadLocalError();
    return need;
  }
}
