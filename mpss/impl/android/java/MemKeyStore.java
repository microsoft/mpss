// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss;

import java.security.KeyPair;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class MemKeyStore {
    private static final ConcurrentMap<String, KeyPair> KeyPairs = new ConcurrentHashMap<>();

    // How many open handles depend on each cached key, so that one handle's close does not evict
    // an entry another handle is still using.
    private static final ConcurrentMap<String, Integer> Holds = new ConcurrentHashMap<>();

    public static void AddKey(String keyName, KeyPair kp) {
        KeyPairs.put(keyName, kp);
    }

    /**
     * Record that one more handle depends on this name's cached key.
     * @param keyName Name of the key being handed to a caller.
     */
    public static void RetainKey(String keyName) {
        Holds.merge(keyName, 1, Integer::sum);
    }

    public static KeyPair GetKey(String keyName) {
        return KeyPairs.get(keyName);
    }

    /**
     * Release one hold on a key, evicting it once none are left. A name with no recorded hold is
     * evicted directly, so a key cached without a handle behind it is not kept alive.
     * @param keyName Name of the key to release.
     */
    public static void RemoveKey(String keyName) {
        if (null == Holds.computeIfPresent(keyName, (name, holds) -> (holds > 1) ? (holds - 1) : null)) {
            KeyPairs.remove(keyName);
        }
    }

    /**
     * Drop a key regardless of how many holds remain. Deleting a key invalidates every handle to
     * it, so the entry must not survive on another handle's hold.
     * @param keyName Name of the key to drop.
     */
    public static void PurgeKey(String keyName) {
        Holds.remove(keyName);
        KeyPairs.remove(keyName);
    }

    public static void RemoveAllKeys() {
        Holds.clear();
        KeyPairs.clear();
    }
}
