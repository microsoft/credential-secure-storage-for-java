// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.implementation.posix.internal.GnomeKeyringLibrary;
import com.microsoft.credentialstorage.model.TokenPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * GNOME Keyring store for a token pair.
 */
public final class GnomeKeyringBackedTokenPairStore extends GnomeKeyringBackedSecureStore<TokenPair> {
    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedTokenPairStore.class);
    public static final String ACCESS_TOKEN = "/accessToken";
    public static final String REFRESH_TOKEN = "/refreshToken";

    /**
     * Read a secret from GNOME Keyring using its simple password API
     *
     * @param key for which a secret is associated with
     * @return secret
     */
    @Override
    public TokenPair get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting {} for {}", getType(), key);

        final char[] secretAccess = getSecret(key + ACCESS_TOKEN);
        final char[] secretRefresh = getSecret(key + REFRESH_TOKEN);

        // no token found
        if (secretAccess == null && secretRefresh == null) {
            return null;
        }

        return new TokenPair(secretAccess, secretRefresh);
    }

    @Override
    public boolean add(final String key, TokenPair secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");

        logger.info("Adding a {} for {}", getType(), key);

        int result = INSTANCE.gnome_keyring_store_password_sync(
                SCHEMA,
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, // save to disk
                key + ACCESS_TOKEN, //display name
                new String(secret.getAccessToken().getValue()),
                //attributes list
                "Type", getType(),
                "Key", key,
                null
        );

        checkResult(result, "Could not save access token to the storage.");

        result = INSTANCE.gnome_keyring_store_password_sync(
                SCHEMA,
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, // save to disk
                key + REFRESH_TOKEN, //display name
                new String(secret.getRefreshToken().getValue()),
                //attributes list
                "Type", getType(),
                "Key", key,
                null
        );

        return checkResult(result, "Could not save refresh token to the storage.");
    }

    @Override
    protected String getType() {
        return "OAuth2Token";
    }
}
