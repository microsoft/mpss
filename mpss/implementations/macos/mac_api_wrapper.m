// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Global dictionary to store SecKeyRef instances
static NSMutableDictionary<NSString *, id> *_keyStore;

void InitializeKeyStore() 
{
    if (!_keyStore) {
        _keyStore = [[NSMutableDictionary alloc] init];
    }
}

void SetThreadLocalError(NSString *error) {
    NSLog(@"%@", error);
    [[NSThread currentThread].threadDictionary setObject:error forKey:@"MyThreadLocalError"];
}

NSString* GetThreadLocalError() {
    return [[NSThread currentThread].threadDictionary objectForKey:@"MyThreadLocalError"];
}

NSString *GetKeyLabel(const char* keyName)
{
    NSString *keyLabel = [[NSString alloc] initWithUTF8String:keyName];
    NSString *keyNameWithPrefix = [NSString stringWithFormat:@"com.microsoft.mpss.%@", keyLabel];
    return keyNameWithPrefix;
}

void StoreKey(NSString *keyLabel, SecKeyRef keyRef)
{
    InitializeKeyStore();

    if (keyLabel && keyRef) {
        // Store the key
        _keyStore[keyLabel] = (__bridge id)keyRef;

        // Ensure the key stays alive
        CFRetain(keyRef);
    }
}

SecKeyRef GetKey(NSString* keyLabel)
{
    InitializeKeyStore();

    return (__bridge SecKeyRef)(_keyStore[keyLabel]);
}

void RemoveKey(NSString *keyLabel)
{
    InitializeKeyStore();

    SecKeyRef keyRef = (__bridge SecKeyRef)(_keyStore[keyLabel]);

    if (keyRef) {
        CFRelease(keyRef);
        [_keyStore removeObjectForKey:keyLabel];
    }
}

int GetKeySize(SecKeyRef keyRef)
{
    // Retrieve the key size
    CFDictionaryRef attrs = SecKeyCopyAttributes(keyRef);
    NSNumber *keySizeNumber = (__bridge NSNumber *)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
    int bitSize = [keySizeNumber intValue];
    CFRelease(attrs);

    return bitSize;
}

SecKeyAlgorithm GetAlgorithm(int signatureType)
{
    switch(signatureType) {
        case 1: // ECDSA SHA 256
            return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
        case 2: // ECDSA SHA 384
            return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
        case 3: // ECDSA SHA 512
            return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
        default:
            NSLog(@"Unsupported signature type");
            return NULL;
    }
}

////////////////////////////////////////////////////////
// From here on below, the public functions
////////////////////////////////////////////////////////

void RemoveKeyMacOS(const char *keyName)
{
    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);
        RemoveKey(keyLabel);
    }
}

bool OpenExistingKeyMacOS(const char* keyName, int* bitSize)
{
    if (keyName == NULL || bitSize == NULL) {
        return false;
    }

    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);
        SecKeyRef keyRef = GetKey(keyLabel);

        if (keyRef) {
            // Already exists
            NSLog(@"Found existing key in local dictionary");
            *bitSize = GetKeySize(keyRef);
            return true;
        }

        NSLog(@"Did not find key in local dictionary, querying from OS");

        NSDictionary *query = @{
            (id)kSecClass: (__bridge id)kSecClassKey,
            (id)kSecAttrApplicationTag: [keyLabel dataUsingEncoding:NSUTF8StringEncoding],
            (id)kSecReturnRef: @YES
        };

        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&keyRef);

        if (status == errSecSuccess) {
            NSLog(@"Successfully retrieved key: %@", keyRef);
            StoreKey(keyLabel, keyRef);

            *bitSize = GetKeySize(keyRef);
            return true;
        } else {
            NSString *error = [NSString stringWithFormat:@"Failed to retrieve key with status: %d", (int)status];
            SetThreadLocalError(error);
        }

        return false;
    }
}

bool CreateKeyMacOS(const char *keyName, int bitSize)
{
    // Define key attributes
    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);

        int keyBitSize = 0;
        switch (bitSize) {
        case 1:
            keyBitSize = 256;
            break;
        case 2:
            keyBitSize = 384;
            break;
        case 3:
            keyBitSize = 521;
            break;
        default:
            NSLog(@"Invalid bitSize for key creation: %d", bitSize);
            return false;
        }

        NSLog(@"Creating bit size: %d", bitSize);
        NSDictionary *keyAttributes = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @(keyBitSize),
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: [keyLabel dataUsingEncoding:NSUTF8StringEncoding]
        };

        // Generate the key
        CFErrorRef error = NULL;
        SecKeyRef keyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, &error);

        if (keyRef == NULL) {
            NSError *err = CFBridgingRelease(error);
            NSString* error = [NSString stringWithFormat:@"Failed to generate key: %@", err];
            SetThreadLocalError(error);
            return false;
        } else {
            NSLog(@"Key generated successfully!");
            StoreKey(keyLabel, keyRef);
        }

        return true;
    }
}

bool SignHashMacOS(const char *keyName, int signatureType, const uint8_t *hash, size_t hashSize, uint8_t** signature, size_t* signatureSize)
{
    if (keyName == NULL || hash == NULL || signature == NULL || signatureSize == NULL) {
        return false;
    }

    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);
        SecKeyRef keyRef = GetKey(keyLabel);

        if (keyRef == NULL) {
            NSLog(@"Key not found");
            return false;
        }

        NSData *hashData = [NSData dataWithBytes:hash length:hashSize];

        SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
        if (algorithm == NULL) {
            NSString* error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
            SetThreadLocalError(error);
            return false;
        }

        CFErrorRef error = NULL;
        CFDataRef signatureData = SecKeyCreateSignature(keyRef, algorithm, (__bridge CFDataRef)hashData, &error);

        if (signatureData == NULL) {
            NSError *err = CFBridgingRelease(error);
            NSString* error = [NSString stringWithFormat:@"Failed to sign hash: %@", err];
            SetThreadLocalError(error);
            return false;
        }

        *signatureSize = CFDataGetLength(signatureData);
        *signature = (uint8_t*)malloc(*signatureSize);
        memcpy(*signature, CFDataGetBytePtr(signatureData), *signatureSize);
        NSLog(@"Signature created successfully. Signature size: %lu", *signatureSize);

        CFRelease(signatureData);

        return true;
    }
}

bool VerifySignatureMacOS(const char *keyName, int signatureType, const uint8_t *hash, size_t hashSize, const uint8_t *signature, size_t signatureSize)
{
    if (keyName == NULL || hash == NULL || signature == NULL) {
        return false;
    }

    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);
        SecKeyRef keyRef = GetKey(keyLabel);

        if (keyRef == NULL) {
            NSString* error = @"Key not found";
            SetThreadLocalError(error);
            return false;
        }

        NSData *hashData = [NSData dataWithBytes:hash length:hashSize];
        NSData *signatureData = [NSData dataWithBytes:signature length:signatureSize];

        SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
        if (algorithm == NULL) {
            NSString* error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
            SetThreadLocalError(error);
            return false;
        }

        SecKeyRef publicKeyRef = SecKeyCopyPublicKey(keyRef);
        if (!publicKeyRef) {
            NSString* error = @"Could not copy public key";
            SetThreadLocalError(error);
            return false;
        }

        CFErrorRef error = NULL;
        bool result = SecKeyVerifySignature(publicKeyRef, algorithm, (__bridge CFDataRef)hashData, (__bridge CFDataRef)signatureData, &error);

        // Release public key
        CFRelease(publicKeyRef);

        if (!result) {
            NSError *err = CFBridgingRelease(error);
            NSString* error = [NSString stringWithFormat:@"Failed to verify signature: %@", err];
            SetThreadLocalError(error);
            return false;
        }

        return true;
    }
}

bool GetPublicKeyMacOS(const char *keyName, uint8_t **pk, size_t *pkSize)
{
    if (NULL == keyName || NULL == pk || NULL == pkSize) {
        return false;
    }

    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);
        SecKeyRef keyRef = GetKey(keyLabel);

        if (keyRef == NULL) {
            NSString* error = @"Key not found";
            SetThreadLocalError(error);
            return false;
        }

        SecKeyRef publicKeyRef = SecKeyCopyPublicKey(keyRef);
        if (publicKeyRef == NULL) {
            NSString *error = @"Could not copy public key";
            SetThreadLocalError(error);
            return false;
        }

        // Get PK data
        CFErrorRef error = NULL;
        CFDataRef pkData = SecKeyCopyExternalRepresentation(publicKeyRef, &error);

        if (!pkData) {
            NSError *err = CFBridgingRelease(error);
            NSString *errStr = [NSString stringWithFormat:@"Failed to copy public key external representation: %@", err];
            SetThreadLocalError(errStr);
            CFRelease(publicKeyRef);
            return false;
        }

        // Get raw bytes
        CFIndex length = CFDataGetLength(pkData);
        const UInt8 *pkBytes = CFDataGetBytePtr(pkData);

        *pk = malloc(length);
        if (! *pk) {
            CFRelease(pkData);
            CFRelease(publicKeyRef);
            SetThreadLocalError(@"Could not allocate public key memory buffer");
            return false;
        }

        *pkSize = length;
        memcpy(*pk, pkBytes, length);
        NSLog(@"Successfully copied PK to memory buffer");

        CFRelease(pkData);
        CFRelease(publicKeyRef);

        return true;
    }
}

bool DeleteKeyMacOS(const char *keyName)
{
    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);
        SecKeyRef keyRef = GetKey(keyLabel);

        if (keyRef) {
            RemoveKey(keyLabel);
        }

        NSDictionary *query = @{
            (id)kSecClass: (__bridge id)kSecClassKey,
            (id)kSecAttrApplicationTag: [keyLabel dataUsingEncoding:NSUTF8StringEncoding]
        };

        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

        if (status == errSecSuccess) {
            NSLog(@"Successfully deleted key");
            return true;
        } else {
            NSString *error = [NSString stringWithFormat:@"Failed to delete key with status: %d", (int)status];
            SetThreadLocalError(error);
        }

        return false;
    }
}

const char* GetLastErrorMacOS()
{
    @autoreleasepool {
        NSString* error = GetThreadLocalError();
        if (error) {
            return [error UTF8String];
        }

        return NULL;
    }
}
