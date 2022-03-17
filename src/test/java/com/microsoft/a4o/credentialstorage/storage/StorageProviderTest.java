// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage;

import com.microsoft.a4o.credentialstorage.secret.Token;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class StorageProviderTest {

    private StorageProvider.NonPersistentStoreGenerator<Token> generator = new StorageProvider.NonPersistentStoreGenerator<Token>() {
        @Override
        public SecretStore<Token> getInsecureNonPersistentStore() {
            return getStore(false);
        }

        @Override
        public SecretStore<Token> getSecureNonPersistentStore() {
            return null;
        }
    };

    @Test
    public void withAvailableSecureStore_shouldReturnSecureStore() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<Token> actual = StorageProvider.getStore(true, StorageProvider.SecureOption.MUST, candidates, generator);
        assertTrue(actual.isSecure());
    }

    @Test
    public void noAvailableSecureStore_shouldReturnNull() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();

        final SecretStore<Token> actual = StorageProvider.getStore(true, StorageProvider.SecureOption.MUST, candidates, generator);
        assertNull(actual);
    }

    @Test
    public void nonPersisted_MustBeSecure_shouldUseGenerator() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<Token> actual = StorageProvider.getStore(false, StorageProvider.SecureOption.MUST, candidates, generator);
        assertNull(actual);
    }

    @Test
    public void nonPersisted_doNotCareSecurity_shouldUseGenerator() throws Exception {
        List<SecretStore<Token>> candidates = new ArrayList<SecretStore<Token>>();
        //Add one persisted secure store to it
        candidates.add(getStore(true));

        final SecretStore<Token> actual = StorageProvider.getStore(false, StorageProvider.SecureOption.PREFER, candidates, generator);
        assertFalse(actual.isSecure());
    }

    private SecretStore<Token> getStore(final boolean secure) {
        return new SecretStore<Token>() {
            @Override
            public Token get(String key) { return null; }

            @Override
            public boolean delete(String key) { return false; }

            @Override
            public boolean add(String key, Token secret) { return false; }

            @Override
            public boolean isSecure() {
                return secure;
            }
        };
    }

}