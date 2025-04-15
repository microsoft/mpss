// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.research.mpss;

import java.security.KeyPair;
import java.util.HashMap;

public class MemKeyStore {
    private static HashMap<String, KeyPair> KeyPairs = new HashMap<>();

    public static void AddKey(String keyName, KeyPair kp) {
        KeyPairs.put(keyName, kp);
    }

    public static KeyPair GetKey(String keyName) {
        return KeyPairs.getOrDefault(keyName, null);
    }

    public static void RemoveKey(String keyName) {
        KeyPairs.remove(keyName);
    }

    public static void RemoveAllKeys() {
        KeyPairs.clear();
    }
}
