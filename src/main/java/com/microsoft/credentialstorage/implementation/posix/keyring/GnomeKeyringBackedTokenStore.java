// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.implementation.posix.internal.GnomeKeyringLibrary;
import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * GNOME Keyring store for a token.
 */
public final class GnomeKeyringBackedTokenStore extends GnomeKeyringBackedSecureStore<StoredToken> {
    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedTokenStore.class);

    /**
     * Read a secret from GNOME Keyring using its simple password API
     *
     * @param key for which a secret is associated with
     * @return secret
     */
    @Override
    public StoredToken get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting {} for {}", getType(), key);

        final char[] secret = getSecret(key);
        return secret != null ? new StoredToken(secret, StoredTokenType.PERSONAL) : null;
    }

    @Override
    public boolean add(final String key, StoredToken secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");

        logger.info("Adding a {} for {}", getType(), key);

        final int result = INSTANCE.gnome_keyring_store_password_sync(
                SCHEMA,
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, // save to disk
                key, //display name
                new String(secret.getValue()),
                //attributes list
                "Type", getType(),
                "Key", key,
                null
        );

        return checkResult(result, "Could not save secret to the storage.");
    }

    @Override
    protected String getType() {
        return "Personal Access Token";
    }
}
