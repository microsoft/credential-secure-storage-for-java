// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.libsecret;

import com.microsoft.credentialstorage.implementation.posix.internal.GLibLibrary;
import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenPair;
import com.microsoft.credentialstorage.model.StoredTokenType;
import com.sun.jna.ptr.PointerByReference;

import java.util.Objects;

/**
 * Libsecret store for a token pair.
 */
public final class LibSecretBackedTokenPairStore extends LibSecretBackedSecureStore<StoredTokenPair> {
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

        final PointerByReference error = new PointerByReference();
        try {
            boolean result = writeSecret(key + ACCESS_TOKEN,
                    secret.getAccessToken().getType().getDescription(),
                    secret.getAccessToken().getValue(), error);
            if (!result || !checkResult(error, "Could not save access token to the storage.")) {
                return false;
            }

            result = writeSecret(key + REFRESH_TOKEN,
                    secret.getRefreshToken().getType().getDescription(),
                    secret.getRefreshToken().getValue(), error);
            return result && checkResult(error, "Could not save refresh token to the storage.");
        } finally {
            if (error.getValue() != null) {
                GLibLibrary.INSTANCE.g_error_free(error.getValue());
            }
        }
    }

    @Override
    public boolean delete(String key) {
        Objects.requireNonNull(key, "key cannot be null");
        logger.info("Deleting {} for {}", getType(), key);

        boolean result;

        final PointerByReference accessError = new PointerByReference();
        try {
            boolean accessResult = deleteSecret(key + ACCESS_TOKEN, accessError);
            result = accessResult && checkResult(accessError, "Could not delete access token from storage");
        } finally {
            if (accessError.getValue() != null) {
                GLibLibrary.INSTANCE.g_error_free(accessError.getValue());
            }
        }

        final PointerByReference refreshError = new PointerByReference();
        try {
            boolean refreshResult = deleteSecret(key + REFRESH_TOKEN, accessError);
            result &= refreshResult && checkResult(refreshError, "Could not delete refresh token from storage");
        } finally {
            if (accessError.getValue() != null) {
                GLibLibrary.INSTANCE.g_error_free(accessError.getValue());
            }
        }

        return result;
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
