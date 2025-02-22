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
            return true;
        }

        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrLabel: keyLabel,
            (__bridge id)kSecReturnRef: @YES
        };

        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&keyRef);

        if (status == errSecSuccess) {
            NSLog(@"Successfully retrieved key: %@", keyRef);
            StoreKey(keyLabel, keyRef);

            // Retrieve the key size
            CFDataRef keyData = SecKeyCopyExternalRepresentation(keyRef, NULL);
            if (keyData) {
                *bitSize = (int)(CFDataGetLength(keyData) * 8);
                CFRelease(keyData);
            }

            return true;
        } else {
            NSLog(@"Failed to retrieve key with status: %d", (int)status);
        }

        return false;
    }
}

bool CreateKeyMacOS(const char *keyName, int bitSize)
{
    // Define key attributes
    @autoreleasepool {
        NSString *keyLabel = GetKeyLabel(keyName);

        NSDictionary *keyAttributes = @{
            (__bridge id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits: @(bitSize),
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrCanSign: @YES,
            (__bridge id)kSecAttrCanVerify: @YES,
            (__bridge id)kSecAttrApplicationTag: keyLabel
        };

        // Generate the key
        CFErrorRef error = NULL;
        SecKeyRef keyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, &error);

        if (keyRef == NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"Failed to generate key: %@", err);
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

        SecKeyAlgorithm algorithm = NULL;
        switch(signatureType) {
            case 0: // ECDSA SHA 256
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256;
                break;
            case 1: // ECDSA SHA 384
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384;
                break;
            case 2: // ECDSA SHA 512
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512;
                break;
            default:
                NSLog(@"Unsupported signature type");
                return false;
        }

        CFErrorRef error = NULL;
        CFDataRef signatureData = SecKeyCreateSignature(keyRef, algorithm, (__bridge CFDataRef)hashData, &error);

        if (signatureData == NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"Failed to sign hash: %@", err);
            return false;
        }

        *signatureSize = CFDataGetLength(signatureData);
        *signature = (uint8_t*)malloc(*signatureSize);
        memcpy(*signature, CFDataGetBytePtr(signatureData), *signatureSize);

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
            NSLog(@"Key not found");
            return false;
        }

        NSData *hashData = [NSData dataWithBytes:hash length:hashSize];
        NSData *signatureData = [NSData dataWithBytes:signature length:signatureSize];

        SecKeyAlgorithm algorithm = NULL;
        switch(signatureType) {
            case 0: // ECDSA SHA 256
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256;
                break;
            case 1: // ECDSA SHA 384
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA384;
                break;
            case 2: // ECDSA SHA 512
                algorithm = kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA512;
                break;
            default:
                NSLog(@"Unsupported signature type");
                return false;
        }

        CFErrorRef error = NULL;
        bool result = SecKeyVerifySignature(keyRef, algorithm, (__bridge CFDataRef)hashData, (__bridge CFDataRef)signatureData, &error);

        if (!result) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"Failed to verify signature: %@", err);
            return false;
        }

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
            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrLabel: keyLabel
        };

        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

        if (status == errSecSuccess) {
            NSLog(@"Successfully deleted key");
            return true;
        } else {
            NSLog(@"Failed to delete key with status: %d", (int)status);
        }

        return false;
    }
}
