// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.model.StoredCredential;

import java.util.Objects;

/**
 * GNOME Keyring store for a credential.
 */
public final class GnomeKeyringBackedCredentialStore extends GnomeKeyringBackedSecureStore<StoredCredential> {
    @Override
    public boolean add(final String key, StoredCredential secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "secret cannot be null");

        if (INSTANCE != null && SCHEMA != null) {
            logger.info("Adding a {} for {}", getType(), key);

            final int result = writeSecret(key, secret.getUsername(), secret.getPassword());

            return checkResult(result, "Could not save secret to the storage.");
        }

        logger.warn("Gnome Keyring is not available.");
        return false;
    }

    @Override
    protected StoredCredential create(String username, char[] secret) {
        return new StoredCredential(username, secret);
    }

    @Override
    protected String getType() {
        return "Credential";
    }
}
