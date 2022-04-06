// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import com.microsoft.a4o.credentialstorage.secret.TokenType;

import java.util.Objects;

/**
 * Credential Manager store for a token pair.
 */
public final class CredManagerBackedTokenPairStore extends CredManagerBackedSecureStore<TokenPair> {
    private static final String ACCESS_TOKEN = "/accessToken";
    private static final String REFRESH_TOKEN = "/refreshToken";

    @Override
    public TokenPair get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting secret for {}", key);

        final Token accessToken = readSecret(key + ACCESS_TOKEN,
                credential -> new Token(getSecret(credential), TokenType.ACCESS));
        final Token refreshToken = readSecret(key + REFRESH_TOKEN,
                credential -> new Token(getSecret(credential), TokenType.REFRESH));

        // no token found
        if (accessToken == null && refreshToken == null) {
            return null;
        }

        return new TokenPair(accessToken, refreshToken);
    }

    @Override
    public boolean add(final String key, final TokenPair secret) {
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
    protected TokenPair create(final String username, final char[] secret) {
        // not used
        return null;
    }
}
