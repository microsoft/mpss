// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss;

import java.security.KeyPair;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

public class MemKeyStore {
    private static final ConcurrentMap<String, KeyPair> KeyPairs = new ConcurrentHashMap<>();

    // How many open handles depend on each cached key, so that one handle's close does not evict
    // an entry another handle is still using.
    private static final ConcurrentMap<String, Integer> Holds = new ConcurrentHashMap<>();

    // Which entry each hold was taken on. A name can be deleted and created again while a handle to
    // the old key is still alive, and that handle's release must not be charged against the new
    // key. A release for a generation the cache has moved past therefore does nothing. A generation
    // is established when a name starts being cached and kept while it stays cached; only deleting
    // ends one, which is what makes the next create a new one. Generations are never reused.
    private static final ConcurrentMap<String, Long> Generations = new ConcurrentHashMap<>();

    private static final AtomicLong NextGeneration = new AtomicLong();

    public static void AddKey(String keyName, KeyPair kp) {
        KeyPairs.put(keyName, kp);
        Generations.computeIfAbsent(keyName, name -> NextGeneration.incrementAndGet());
    }

    /**
     * Record that one more handle depends on this name's cached key.
     * @param keyName Name of the key being handed to a caller.
     * @return The generation the hold was taken on, to be handed back to RemoveKey.
     */
    public static long RetainKey(String keyName) {
        Holds.merge(keyName, 1, Integer::sum);
        return Generations.getOrDefault(keyName, 0L);
    }

    public static KeyPair GetKey(String keyName) {
        return KeyPairs.get(keyName);
    }

    /**
     * Release one hold on a key, evicting it once none are left. A name with no recorded hold is
     * evicted directly, so a key cached without a handle behind it is not kept alive. A release for
     * a generation this name has moved past does nothing: whatever holds the name now belongs to
     * someone else.
     * @param keyName Name of the key to release.
     * @param generation The generation the hold was taken on.
     */
    public static void RemoveKey(String keyName, long generation) {
        if (!Generations.getOrDefault(keyName, 0L).equals(generation)) {
            return;
        }
        if (null == Holds.computeIfPresent(keyName, (name, holds) -> (holds > 1) ? (holds - 1) : null)) {
            Generations.remove(keyName);
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
        Generations.remove(keyName);
        KeyPairs.remove(keyName);
    }

    public static void RemoveAllKeys() {
        Holds.clear();
        Generations.clear();
        KeyPairs.clear();
    }
}
