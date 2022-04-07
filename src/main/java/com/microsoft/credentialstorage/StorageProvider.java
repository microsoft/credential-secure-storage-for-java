// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage;

import com.microsoft.credentialstorage.model.StoredCredential;
import com.microsoft.credentialstorage.model.StoredSecret;
import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenPair;
import com.microsoft.credentialstorage.implementation.macosx.KeychainSecurityBackedCredentialStore;
import com.microsoft.credentialstorage.implementation.macosx.KeychainSecurityBackedTokenPairStore;
import com.microsoft.credentialstorage.implementation.macosx.KeychainSecurityBackedTokenStore;
import com.microsoft.credentialstorage.implementation.macosx.KeychainSecurityCliStore;
import com.microsoft.credentialstorage.implementation.memory.InsecureInMemoryStore;
import com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringBackedCredentialStore;
import com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringBackedTokenPairStore;
import com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringBackedTokenStore;
import com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringBackedSecureStore;
import com.microsoft.credentialstorage.implementation.windows.CredManagerBackedCredentialStore;
import com.microsoft.credentialstorage.implementation.windows.CredManagerBackedSecureStore;
import com.microsoft.credentialstorage.implementation.windows.CredManagerBackedTokenPairStore;
import com.microsoft.credentialstorage.implementation.windows.CredManagerBackedTokenStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Returns a store for credential, token or token pair for the requested security level..
 */
public final class StorageProvider {
    /**
     * Option for requesting a store defining whether it is required to be secure or not.
     */
    public enum SecureOption {
        /**
         * The store must be secure, i.e. generally the storage needs to be password protected
         * and data potentially is encrypted
         *
         * However, this program makes no assertion on *how* secure the storage really is.  It's only
         * an attribute on the storage
         */
        MUST,

        /**
         * Prefer a secure storage, but if none is available, a unprotected, non secure storage will be returned
         */
        PREFER
    }

    private static final Logger logger = LoggerFactory.getLogger(StorageProvider.class);

    private static final List<SecretStore<StoredToken>> PERSISTED_TOKEN_STORE_CANDIDATES;

    private static final List<SecretStore<StoredTokenPair>> PERSISTED_TOKENPAIR_STORE_CANDIDATES;

    private static final List<SecretStore<StoredCredential>> PERSISTED_CREDENTIAL_STORE_CANDIDATES;

    private StorageProvider() {
    }

    static {
        List<SecretStore<StoredToken>> tokenStoreCandidates = new ArrayList<>();
        List<SecretStore<StoredTokenPair>> tokenPairStoreCandidates = new ArrayList<>();
        List<SecretStore<StoredCredential>> credentialStoreCandidates = new ArrayList<>();

        if (CredManagerBackedSecureStore.isSupported()) {
            tokenStoreCandidates.add(new CredManagerBackedTokenStore());
            credentialStoreCandidates.add(new CredManagerBackedCredentialStore());
            tokenPairStoreCandidates.add(new CredManagerBackedTokenPairStore());
        }

        if (KeychainSecurityCliStore.isSupported()) {
            tokenStoreCandidates.add(new KeychainSecurityBackedTokenStore());
            credentialStoreCandidates.add(new KeychainSecurityBackedCredentialStore());
            tokenPairStoreCandidates.add(new KeychainSecurityBackedTokenPairStore());
        }

        if (GnomeKeyringBackedSecureStore.isSupported()) {
            tokenStoreCandidates.add(new GnomeKeyringBackedTokenStore());
            credentialStoreCandidates.add(new GnomeKeyringBackedCredentialStore());
            tokenPairStoreCandidates.add(new GnomeKeyringBackedTokenPairStore());
        }

        PERSISTED_TOKEN_STORE_CANDIDATES = tokenStoreCandidates;
        PERSISTED_TOKENPAIR_STORE_CANDIDATES = tokenPairStoreCandidates;
        PERSISTED_CREDENTIAL_STORE_CANDIDATES = credentialStoreCandidates;
    }

    /**
     * Returns a token store for the specific requirements.
     *
     * @param persist true for persistent storage
     * @param secureOption secure or non-secure storage
     * @return store
     */
    public static SecretStore<StoredToken> getTokenStorage(final boolean persist, final SecureOption secureOption) {
        Objects.requireNonNull(secureOption, "secureOption cannot be null");

        logger.info("Getting a {} token store that {} be secure", persist ? "persistent" : "non-persistent",
                secureOption == SecureOption.MUST ? "must" : "could");

        final NonPersistentStoreGenerator<StoredToken> inMemoryStoreGenerator = new NonPersistentStoreGenerator<>() {
            @Override
            public SecretStore<StoredToken> getInsecureNonPersistentStore() {
                return new InsecureInMemoryStore<>();
            }

            @Override
            public SecretStore<StoredToken> getSecureNonPersistentStore() {
                logger.warn("Do not have any secure non-persistent stores available.");
                return null;
            }
        };

        return getStore(persist, secureOption, PERSISTED_TOKEN_STORE_CANDIDATES, inMemoryStoreGenerator);
    }

    /**
     * Returns a token pair store for the specific requirements.
     *
     * @param persist true for persistent storage
     * @param secureOption secure or non-secure storage
     * @return store
     */
    public static SecretStore<StoredTokenPair> getTokenPairStorage(final boolean persist, final SecureOption secureOption) {
        Objects.requireNonNull(secureOption, "secureOption cannot be null");

        logger.info("Getting a {} tokenPair store that {} be secure", persist ? "persistent" : "non-persistent",
                secureOption == SecureOption.MUST ? "must" : "could");

        final NonPersistentStoreGenerator<StoredTokenPair> inMemoryStoreGenerator = new NonPersistentStoreGenerator<>() {
            @Override
            public SecretStore<StoredTokenPair> getInsecureNonPersistentStore() {
                return new InsecureInMemoryStore<>();
            }

            @Override
            public SecretStore<StoredTokenPair> getSecureNonPersistentStore() {
                logger.warn("Do not have any secure non-persistent stores available.");
                return null;
            }
        };

        return getStore(persist, secureOption, PERSISTED_TOKENPAIR_STORE_CANDIDATES, inMemoryStoreGenerator);
    }

    /**
     * Returns a credential store for the specific requirements.
     *
     * @param persist true for persistent storage
     * @param secureOption secure or non-secure storage
     * @return store
     */
    public static SecretStore<StoredCredential> getCredentialStorage(final boolean persist, final SecureOption secureOption) {
        Objects.requireNonNull(secureOption, "secureOption cannot be null");

        logger.info("Getting a {} credential store that {} be secure", persist ? "persistent" : "non-persistent",
                secureOption == SecureOption.MUST ? "must" : "could");

        final NonPersistentStoreGenerator<StoredCredential> inMemoryStoreGenerator = new NonPersistentStoreGenerator<>() {
            @Override
            public SecretStore<StoredCredential> getInsecureNonPersistentStore() {
                return new InsecureInMemoryStore<>();
            }

            @Override
            public SecretStore<StoredCredential> getSecureNonPersistentStore() {
                logger.warn("Do not have any secure non-persistent stores available.");
                return null;
            }
        };

        return getStore(persist, secureOption, PERSISTED_CREDENTIAL_STORE_CANDIDATES, inMemoryStoreGenerator);
    }

    private static <E extends StoredSecret> SecretStore<E> findSecureStore(final List<SecretStore<E>> stores) {
        for (final SecretStore<E> store : stores) {
            if (store.isSecure()) {
                return store;
            }
        }

        return null;
    }

    private static <E extends StoredSecret> SecretStore<E> findPersistedStore(final SecureOption secureOption,
                                                                              final List<SecretStore<E>> stores) {
        SecretStore<E> candidate = findSecureStore(stores);

        if (candidate == null && secureOption == SecureOption.PREFER) {
            // just return any store from the list since none of them is secure
            if (!stores.isEmpty()) {
                candidate = stores.get(0);
            }
        }

        // nullable
        return candidate;
    }

    static <E extends StoredSecret> SecretStore<E> getStore(final boolean persist,
                                                            final SecureOption secureOption,
                                                            final List<SecretStore<E>> stores,
                                                            final NonPersistentStoreGenerator<E> nonPersistentStoreGenerator) {
        Objects.requireNonNull(nonPersistentStoreGenerator, "nonPersistentStoreGenerator cannot be null.");
        Objects.requireNonNull(stores, "stores cannot be null.");

        SecretStore<E> candidate;
        if (persist) {
            candidate = findPersistedStore(secureOption, stores);
        } else {
            // not persisted
            candidate = nonPersistentStoreGenerator.getSecureNonPersistentStore();
            if (candidate == null && secureOption == SecureOption.PREFER) {
                candidate = nonPersistentStoreGenerator.getInsecureNonPersistentStore();
            }
        }

        return candidate;
    }

    interface NonPersistentStoreGenerator<E extends StoredSecret> {
        SecretStore<E> getInsecureNonPersistentStore();
        SecretStore<E> getSecureNonPersistentStore();
    }
}
