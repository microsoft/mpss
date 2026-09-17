// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss;

import java.security.KeyPair;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class MemKeyStore {
    private static final ConcurrentMap<String, KeyPair> KeyPairs = new ConcurrentHashMap<>();

    public static void AddKey(String keyName, KeyPair kp) {
        KeyPairs.put(keyName, kp);
    }

    public static KeyPair GetKey(String keyName) {
        return KeyPairs.get(keyName);
    }

    public static void RemoveKey(String keyName) {
        KeyPairs.remove(keyName);
    }

    public static void RemoveAllKeys() {
        KeyPairs.clear();
    }
}
