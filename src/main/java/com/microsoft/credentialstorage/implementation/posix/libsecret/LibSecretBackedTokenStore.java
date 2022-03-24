// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.libsecret;

import com.microsoft.credentialstorage.implementation.posix.internal.GLibLibrary;
import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenType;
import com.sun.jna.ptr.PointerByReference;

import java.util.Objects;

/**
 * Libsecret store for a token.
 */
public final class LibSecretBackedTokenStore extends LibSecretBackedSecureStore<StoredToken> {
    @Override
    protected StoredToken create(final String username, final char[] secret) {
        return new StoredToken(secret, StoredTokenType.fromDescription(username));
    }

    @Override
    public boolean add(final String key, final StoredToken token) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(token, "secret cannot be null");

        logger.info("Adding a {} for {}", getType(), key);

        final PointerByReference error = new PointerByReference();
        try {
            return writeSecret(key, token.getType().getDescription(), token.getValue(), error);
        } finally {
            if (error.getValue() != null) {
                GLibLibrary.INSTANCE.g_error_free(error.getValue());
            }
        }
    }

    @Override
    protected String getType() {
        return "Token";
    }
}
