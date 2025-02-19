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

void StoreKey(const char *keyName, SecKeyRef keyRef)
{
    InitializeKeyStore();

    NSString *keyLabel = [[NSString alloc] initWithUTF8String:keyName];
    if (keyLabel && keyRef) {
        // Store the key
        _keyStore[keyLabel] = (__bridge id)keyRef;

        // Ensure the key stays alive
        CFRetain(keyRef);
    }
}

SecKeyRef GetKey(const char* keyName)
{
    InitializeKeyStore();

    NSString *keyLabel = [[NSString alloc] initWithUTF8String:keyName];
    return (__bridge SecKeyRef)(_keyStore[keyLabel]);
}

void RemoveKey(const char *keyName)
{
    InitializeKeyStore();

    NSString *keyLabel = [[NSString alloc] initWithUTF8String:keyName];
    SecKeyRef keyRef = (__bridge SecKeyRef)(_keyStore[keyLabel]);

    if (keyRef) {
        CFRelease(keyRef);
        [_keyStore removeObjectForKey:keyLabel];
    }
}

void OpenExistingKeyMacOS(const char* keyName)
{
    SecKeyRef keyRef = GetKey(keyName);

    if (keyRef) {
        // Already exists
        return;
    }

    NSString *keyLabel = [[NSString alloc] initWithUTF8String:keyName];

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrLabel: keyLabel,
        (__bridge id)kSecReturnRef: @YES
    };

    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&keyRef);

    if (status == errSecSuccess) {
        NSLog(@"Successfully retrieved key: %@", keyRef);
        StoreKey(keyName, keyRef);
    } else {
        NSLog(@"Failed to retrieve key with status: %d", (int)status);
    }
}

void CallCreateKeyMacOS(const char *keyName)
{
    // Define key attributes
    @autoreleasepool {
        NSDictionary *keyAttributes = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrCanSign: @YES,
            (id)kSecAttrCanVerify: @YES,
            (id)kSecAttrApplicationTag: [@"com.microsoft.mpss.testKey" dataUsingEncoding:NSUTF8StringEncoding]
        };

        // Generate the key
        CFErrorRef error = NULL;
        SecKeyRef keyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, &error);

        if (keyRef == NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"Failed to generate key: %@", err);
        } else {
            NSLog(@"Key generated successfully!");

            StoreKey(keyName, keyRef);
        }
    }
}
