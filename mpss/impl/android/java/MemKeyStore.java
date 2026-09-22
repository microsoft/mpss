// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

package com.microsoft.mpss;

import java.security.KeyPair;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

public class MemKeyStore {
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
    private static final class CacheEntry {
        KeyPair kp;
        final long generation;
        int holds;

        CacheEntry(KeyPair kp, long generation) {
            this.kp = kp;
            this.generation = generation;
        }
    }

    private static final ConcurrentMap<String, CacheEntry> Entries = new ConcurrentHashMap<>();

    private static final AtomicLong NextGeneration = new AtomicLong();

    public static void AddKey(String keyName, KeyPair kp) {
        Entries.compute(keyName, (name, existing) -> {
            if (null == existing) {
                return new CacheEntry(kp, NextGeneration.incrementAndGet());
            }
            existing.kp = kp;
            return existing;
        });
    }

    /**
     * Record that one more handle depends on this name's cached key.
     * @param keyName Name of the key being handed to a caller.
     * @return The generation the hold was taken on. The handle keeps it and presents it with every
     *         operation it makes, the release that gives the hold back included, so that a name
     *         deleted and created again can be neither reached nor released through a handle opened
     *         on the key that used to hold it.
     */
    public static long RetainKey(String keyName) {
        final CacheEntry entry = Entries.get(keyName);
        if (null == entry) {
            return 0L;
        }
        entry.holds += 1;
        return entry.generation;
    }

    public static KeyPair GetKey(String keyName) {
        final CacheEntry entry = Entries.get(keyName);
        return (null == entry) ? null : entry.kp;
    }

    /**
     * Fetch a cached key only while the caller's generation still names the entry. Handle
     * operations use this so that a name deleted and created again cannot be reached through a
     * handle opened on the key that used to hold it. There is deliberately no fall back to the key
     * store: a handle whose entry is gone is finished, not a name to resolve again.
     * @param keyName Name of the key to retrieve.
     * @param generation The generation the handle recorded when it opened.
     * @return The cached key if the generation still names the entry, null otherwise.
     */
    public static KeyPair GetKeyForGeneration(String keyName, long generation) {
        final CacheEntry entry = Entries.get(keyName);
        return (null != entry && entry.generation == generation) ? entry.kp : null;
    }

    /**
     * Whether the generation a handle recorded still names what this name holds.
     * @param keyName Name of the key.
     * @param generation The generation the handle recorded when it opened.
     * @return True if the generation is still current for this name.
     */
    public static boolean GenerationIsCurrent(String keyName, long generation) {
        final CacheEntry entry = Entries.get(keyName);
        return null != entry && entry.generation == generation;
    }

    /**
     * Release one hold on a key, evicting it once none are left. A release for a generation this
     * name has moved past does nothing: whatever holds the name now belongs to someone else.
     * @param keyName Name of the key to release.
     * @param generation The generation the hold was taken on.
     */
    public static void RemoveKey(String keyName, long generation) {
        final CacheEntry entry = Entries.get(keyName);
        if (null == entry || entry.generation != generation) {
            return;
        }
        entry.holds -= 1;
        if (entry.holds <= 0) {
            Entries.remove(keyName);
        }
    }

    /**
     * Drop a key regardless of how many holds remain. Deleting a key invalidates every handle to
     * it, so the entry must not survive on another handle's hold.
     * @param keyName Name of the key to drop.
     */
    public static void PurgeKey(String keyName) {
        Entries.remove(keyName);
    }

    public static void RemoveAllKeys() {
        Entries.clear();
    }
}
