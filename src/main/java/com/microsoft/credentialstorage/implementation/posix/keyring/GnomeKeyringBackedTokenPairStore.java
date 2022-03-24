// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenPair;
import com.microsoft.credentialstorage.model.StoredTokenType;

import java.util.Objects;

/**
 * GNOME Keyring store for a token pair.
 */
public final class GnomeKeyringBackedTokenPairStore extends GnomeKeyringBackedSecureStore<StoredTokenPair> {
    private static final String ACCESS_TOKEN = "/accessToken";
    private static final String REFRESH_TOKEN = "/refreshToken";

    @Override
    public StoredTokenPair get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting {} for {}", getType(), key);

        final StoredToken accessToken = readSecret(key + ACCESS_TOKEN,
                (userName, password) -> new StoredToken(password, StoredTokenType.ACCESS));
        final StoredToken refreshToken = readSecret(key + REFRESH_TOKEN,
                (userName, password) -> new StoredToken(password, StoredTokenType.REFRESH));

        // no token found
        if (accessToken == null && refreshToken == null) {
            return null;
        }

        return new StoredTokenPair(accessToken, refreshToken);
    }

    @Override
    public boolean add(final String key, StoredTokenPair secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "secret cannot be null");

        logger.info("Adding a {} for {}", getType(), key);

        int result = writeSecret(key + ACCESS_TOKEN,
                secret.getAccessToken().getType().getDescription(),
                secret.getAccessToken().getValue());
        checkResult(result, "Could not save access token to the storage.");

        result = writeSecret(key + REFRESH_TOKEN,
                secret.getRefreshToken().getType().getDescription(),
                secret.getRefreshToken().getValue());
        return checkResult(result, "Could not save refresh token to the storage.");
    }

    @Override
    public boolean delete(String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Deleting {} for {}", getType(), key);

        int result = deleteSecret(key + ACCESS_TOKEN);
        checkResult(result, "Could not delete access token from storage");

        result = deleteSecret(key + REFRESH_TOKEN);
        return checkResult(result, "Could not delete refresh token from storage");
    }

    @Override
    protected StoredTokenPair create(String username, char[] secret) {
        // not used
        return null;
    }

    @Override
    protected String getType() {
        return "OAuth2Token";
    }
}
