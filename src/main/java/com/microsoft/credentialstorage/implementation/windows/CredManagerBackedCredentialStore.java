// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

import com.microsoft.credentialstorage.model.StoredCredential;

import java.util.Objects;

/**
 * Credential Manager store for a credential.
 */
public final class CredManagerBackedCredentialStore extends CredManagerBackedSecureStore<StoredCredential> {
    @Override
    public boolean add(final String key, final StoredCredential secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "secret cannot be null");

        logger.info("Adding secret for {}", key);

        return writeSecret(key, secret.getUsername(), secret.getPassword());
    }

    @Override
    protected StoredCredential create(final String username, final char[] secret) {
        return new StoredCredential(username, secret);
    }
}
