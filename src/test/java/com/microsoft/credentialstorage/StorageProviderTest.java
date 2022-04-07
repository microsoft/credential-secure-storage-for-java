// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage;

import com.microsoft.credentialstorage.model.StoredToken;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class StorageProviderTest {

    private StorageProvider.NonPersistentStoreGenerator<StoredToken> generator = new StorageProvider.NonPersistentStoreGenerator<StoredToken>() {
        @Override
        public SecretStore<StoredToken> getInsecureNonPersistentStore() {
            return getStore(false);
        }

        @Override
        public SecretStore<StoredToken> getSecureNonPersistentStore() {
            return null;
        }
    };

    @Test
    public void withAvailableSecureStore_shouldReturnSecureStore() throws Exception {
        List<SecretStore<StoredToken>> candidates = new ArrayList<SecretStore<StoredToken>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<StoredToken> actual = StorageProvider.getStore(true, StorageProvider.SecureOption.MUST, candidates, generator);
        assertTrue(actual.isSecure());
    }

    @Test
    public void noAvailableSecureStore_shouldReturnNull() throws Exception {
        List<SecretStore<StoredToken>> candidates = new ArrayList<SecretStore<StoredToken>>();

        final SecretStore<StoredToken> actual = StorageProvider.getStore(true, StorageProvider.SecureOption.MUST, candidates, generator);
        assertNull(actual);
    }

    @Test
    public void nonPersisted_MustBeSecure_shouldUseGenerator() throws Exception {
        List<SecretStore<StoredToken>> candidates = new ArrayList<SecretStore<StoredToken>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<StoredToken> actual = StorageProvider.getStore(false, StorageProvider.SecureOption.MUST, candidates, generator);
        assertNull(actual);
    }

    @Test
    public void nonPersisted_doNotCareSecurity_shouldUseGenerator() throws Exception {
        List<SecretStore<StoredToken>> candidates = new ArrayList<SecretStore<StoredToken>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<StoredToken> actual = StorageProvider.getStore(false, StorageProvider.SecureOption.PREFER, candidates, generator);
        assertFalse(actual.isSecure());
    }

    private SecretStore<StoredToken> getStore(final boolean secure) {
        return new SecretStore<StoredToken>() {
            @Override
            public StoredToken get(String key) { return null; }

            @Override
            public boolean delete(String key) { return false; }

            @Override
            public boolean add(String key, StoredToken secret) { return false; }

            @Override
            public boolean isSecure() {
                return secure;
            }
        };
    }

}