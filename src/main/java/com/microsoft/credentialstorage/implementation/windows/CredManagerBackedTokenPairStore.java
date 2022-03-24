// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenPair;
import com.microsoft.credentialstorage.model.StoredTokenType;

import java.util.Objects;

/**
 * Credential Manager store for a token pair.
 */
public final class CredManagerBackedTokenPairStore extends CredManagerBackedSecureStore<StoredTokenPair> {
    private static final String ACCESS_TOKEN = "/accessToken";
    private static final String REFRESH_TOKEN = "/refreshToken";

    @Override
    public StoredTokenPair get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting secret for {}", key);

        final StoredToken accessToken = readSecret(key + ACCESS_TOKEN,
                credential -> new StoredToken(getSecret(credential), StoredTokenType.ACCESS));
        final StoredToken refreshToken = readSecret(key + REFRESH_TOKEN,
                credential -> new StoredToken(getSecret(credential), StoredTokenType.REFRESH));

        // no token found
        if (accessToken == null && refreshToken == null) {
            return null;
        }

        return new StoredTokenPair(accessToken, refreshToken);
    }

    @Override
    public boolean add(final String key, final StoredTokenPair secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "secret cannot be null");

        logger.info("Adding secret for {}", key);

        return writeSecret(key + ACCESS_TOKEN,
                    secret.getAccessToken().getType().getDescription(), secret.getAccessToken().getValue())
                && writeSecret(key + REFRESH_TOKEN,
                    secret.getRefreshToken().getType().getDescription(), secret.getRefreshToken().getValue());
    }

    @Override
    public boolean delete(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Deleting secret for {}", key);

        return deleteSecret(key + ACCESS_TOKEN) && deleteSecret(key + REFRESH_TOKEN);
    }

    @Override
    protected StoredTokenPair create(final String username, final char[] secret) {
        // not used
        return null;
    }
}
