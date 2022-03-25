// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage;

import com.microsoft.a4o.credentialstorage.helpers.SystemHelper;
import com.microsoft.a4o.credentialstorage.secret.Credential;
import com.microsoft.a4o.credentialstorage.secret.Secret;
import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import com.microsoft.a4o.credentialstorage.storage.macosx.KeychainSecurityBackedCredentialStore;
import com.microsoft.a4o.credentialstorage.storage.macosx.KeychainSecurityBackedTokenPairStore;
import com.microsoft.a4o.credentialstorage.storage.macosx.KeychainSecurityBackedTokenStore;
import com.microsoft.a4o.credentialstorage.storage.memory.InsecureInMemoryStore;
import com.microsoft.a4o.credentialstorage.storage.posix.GnomeKeyringBackedCredentialStore;
import com.microsoft.a4o.credentialstorage.storage.posix.GnomeKeyringBackedTokenPairStore;
import com.microsoft.a4o.credentialstorage.storage.posix.GnomeKeyringBackedTokenStore;
import com.microsoft.a4o.credentialstorage.storage.posix.internal.GnomeKeyringBackedSecureStore;
import com.microsoft.a4o.credentialstorage.storage.windows.CredManagerBackedCredentialStore;
import com.microsoft.a4o.credentialstorage.storage.windows.CredManagerBackedTokenPairStore;
import com.microsoft.a4o.credentialstorage.storage.windows.CredManagerBackedTokenStore;
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

    private static final List<SecretStore<Token>> PERSISTED_TOKEN_STORE_CANDIDATES;

    private static final List<SecretStore<TokenPair>> PERSISTED_TOKENPAIR_STORE_CANDIDATES;

    private static final List<SecretStore<Credential>> PERSISTED_CREDENTIAL_STORE_CANDIDATES;

    private StorageProvider() {
    }

    static {
        List<SecretStore<Token>> tokenStoreCandidates = new ArrayList<>();
        List<SecretStore<TokenPair>> tokenPairStoreCandidates = new ArrayList<>();
        List<SecretStore<Credential>> credentialStoreCandidates = new ArrayList<>();

        if (SystemHelper.isWindows()) {
            tokenStoreCandidates.add(new CredManagerBackedTokenStore());
            credentialStoreCandidates.add(new CredManagerBackedCredentialStore());
            tokenPairStoreCandidates.add(new CredManagerBackedTokenPairStore());
        }

        if (SystemHelper.isMac()) {
            tokenStoreCandidates.add(new KeychainSecurityBackedTokenStore());
            credentialStoreCandidates.add(new KeychainSecurityBackedCredentialStore());
            tokenPairStoreCandidates.add(new KeychainSecurityBackedTokenPairStore());
        }

        if (SystemHelper.isLinux() && GnomeKeyringBackedSecureStore.isGnomeKeyringSupported()) {
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
    public static SecretStore<Token> getTokenStorage(final boolean persist, final SecureOption secureOption) {
        Objects.requireNonNull(secureOption, "secureOption cannot be null");

        logger.info("Getting a {} token store that {} be secure", persist ? "persistent" : "non-persistent",
                secureOption == SecureOption.MUST ? "must" : "could");

        final NonPersistentStoreGenerator<Token> inMemoryStoreGenerator = new NonPersistentStoreGenerator<>() {
            @Override
            public SecretStore<Token> getInsecureNonPersistentStore() {
                return new InsecureInMemoryStore<>();
            }

            @Override
            public SecretStore<Token> getSecureNonPersistentStore() {
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
    public static SecretStore<TokenPair> getTokenPairStorage(final boolean persist, final SecureOption secureOption) {
        Objects.requireNonNull(secureOption, "secureOption cannot be null");

        logger.info("Getting a {} tokenPair store that {} be secure", persist ? "persistent" : "non-persistent",
                secureOption == SecureOption.MUST ? "must" : "could");

        final NonPersistentStoreGenerator<TokenPair> inMemoryStoreGenerator = new NonPersistentStoreGenerator<>() {
            @Override
            public SecretStore<TokenPair> getInsecureNonPersistentStore() {
                return new InsecureInMemoryStore<>();
            }

            @Override
            public SecretStore<TokenPair> getSecureNonPersistentStore() {
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
    public static SecretStore<Credential> getCredentialStorage(final boolean persist, final SecureOption secureOption) {
        Objects.requireNonNull(secureOption, "secureOption cannot be null");

        logger.info("Getting a {} credential store that {} be secure", persist ? "persistent" : "non-persistent",
                secureOption == SecureOption.MUST ? "must" : "could");

        final NonPersistentStoreGenerator<Credential> inMemoryStoreGenerator = new NonPersistentStoreGenerator<>() {
            @Override
            public SecretStore<Credential> getInsecureNonPersistentStore() {
                return new InsecureInMemoryStore<>();
            }

            @Override
            public SecretStore<Credential> getSecureNonPersistentStore() {
                logger.warn("Do not have any secure non-persistent stores available.");
                return null;
            }
        };

        return getStore(persist, secureOption, PERSISTED_CREDENTIAL_STORE_CANDIDATES, inMemoryStoreGenerator);
    }

    private static <E extends Secret> SecretStore<E> findSecureStore(final List<SecretStore<E>> stores) {
        for (final SecretStore<E> store : stores) {
            if (store.isSecure()) {
                return store;
            }
        }

        return null;
    }

    private static <E extends Secret> SecretStore<E> findPersistedStore(final SecureOption secureOption,
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

    static <E extends Secret> SecretStore<E> getStore(final boolean persist,
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

    interface NonPersistentStoreGenerator<E extends Secret> {
        SecretStore<E> getInsecureNonPersistentStore();
        SecretStore<E> getSecureNonPersistentStore();
    }
}
