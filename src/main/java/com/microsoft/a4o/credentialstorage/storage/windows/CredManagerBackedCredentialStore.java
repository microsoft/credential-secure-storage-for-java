// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows;

import com.microsoft.a4o.credentialstorage.secret.Credential;

import java.util.Objects;

/**
 * Credential Manager store for a credential.
 */
public final class CredManagerBackedCredentialStore extends CredManagerBackedSecureStore<Credential> {
    @Override
    public boolean add(final String key, final Credential secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "secret cannot be null");

        logger.info("Adding secret for {}", key);

        return writeSecret(key, secret.getUsername(), secret.getPassword());
    }

    @Override
    protected Credential create(final String username, final char[] secret) {
        return new Credential(username, secret);
    }
}
