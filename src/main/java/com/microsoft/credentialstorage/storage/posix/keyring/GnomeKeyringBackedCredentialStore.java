// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.posix.keyring;

import com.microsoft.credentialstorage.secret.Credential;
import com.microsoft.credentialstorage.storage.posix.internal.GnomeKeyringLibrary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * GNOME Keyring store for a credential.
 */
public final class GnomeKeyringBackedCredentialStore extends GnomeKeyringBackedSecureStore<Credential> {
    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedCredentialStore.class);

    /**
     * Read a secret from GNOME Keyring using its simple password API
     *
     * @param key for which a secret is associated with
     * @return secret
     */
    @Override
    public Credential get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting {} for {}", getType(), key);

        final GnomeKeyringLibrary.PointerToPointer pPassword = new GnomeKeyringLibrary.PointerToPointer();
        char[] secret = null;
        try {
            final int result = INSTANCE.gnome_keyring_find_password_sync(
                    SCHEMA,
                    pPassword,
                    "Type", getType(),
                    "Key", key,
                    null);
            if (checkResult(result, "Could not retrieve secret from storage.")) {
                secret = pPassword.pointer.getString(0).toCharArray();
            }
        } finally {
            if (pPassword.pointer != null) {
                INSTANCE.gnome_keyring_free_password(pPassword.pointer);
            }
        }

        return secret != null ? new Credential(key, secret) : null;
    }

    @Override
    public boolean add(final String key, Credential secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");

        logger.info("Adding a {} for {}", getType(), key);

        final int result = INSTANCE.gnome_keyring_store_password_sync(
                SCHEMA,
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, // save to disk
                key, //display name
                new String(secret.getPassword()),
                //attributes list
                "Type", getType(),
                "Key", key,
                null
        );

        return checkResult(result, "Could not save secret to the storage.");
    }

    @Override
    protected String getType() {
        return "Credential";
    }
}
