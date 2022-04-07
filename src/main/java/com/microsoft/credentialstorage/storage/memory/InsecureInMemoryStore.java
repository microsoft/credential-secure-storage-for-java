// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.memory;

import com.microsoft.credentialstorage.secret.Secret;
import com.microsoft.credentialstorage.storage.SecretStore;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory insecure store based on a hash map.
 *
 * @param <E> secret type to store
 */
public final class InsecureInMemoryStore<E extends Secret> implements SecretStore<E> {

    private final ConcurrentMap<String, E> store = new ConcurrentHashMap<>();

    @Override
    public E get(final String key) {
        return store.get(key);
    }

    @Override
    public boolean delete(final String key) {
        if (store.containsKey(key)) {
            return store.remove(key) != null;
        }

        return true;
    }

    @Override
    public boolean add(final String key, final E secret) {
        return store.put(key, secret) != null;
    }

    @Override
    public boolean isSecure() {
        return false;
    }
}
