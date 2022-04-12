// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * A security token pair, combining access and refresh tokens.
 */
public final class StoredTokenPair implements StoredSecret {
    private final StoredToken accessToken;
    private final StoredToken refreshToken;

    /**
     * Creates a new {@link StoredTokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public StoredTokenPair(final StoredToken accessToken, final StoredToken refreshToken) {
        Objects.requireNonNull(accessToken, "The accessToken parameter is null");
        Objects.requireNonNull(refreshToken, "The refreshToken parameter is null");

        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * Creates a new {@link StoredTokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     * @param parameters Map with additional parameters for the token pair
     */
    public StoredTokenPair(final char[] accessToken, final char[] refreshToken, final Map<String, String> parameters) {
        Objects.requireNonNull(accessToken, "The accessToken parameter is null");
        Objects.requireNonNull(refreshToken, "The refreshToken parameter is null");
        Objects.requireNonNull(parameters, "The parameters parameter is null");

        this.accessToken = new StoredToken(accessToken, StoredTokenType.ACCESS);
        this.refreshToken = new StoredToken(refreshToken, StoredTokenType.REFRESH);
    }

    /**
     * Creates a new {@link StoredTokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public StoredTokenPair(final char[] accessToken, final char[] refreshToken) {
        this(accessToken, refreshToken, Collections.emptyMap());
    }

    /**
     * Access token, used to grant access to resources.
     * @return access token
     */
    public StoredToken getAccessToken() {
        return accessToken;
    }

    /**
     * Refresh token, used to grant new access tokens.
     * @return refresh token
     */
    public StoredToken getRefreshToken() {
        return refreshToken;
    }

    /**
     * Clear the token pair value.
     */
    @Override
    public void clear() {
        accessToken.clear();
        refreshToken.clear();
    }

    /**
     * Compares an object to this.
     *
     * @param o The object to compare.
     * @return True if equal; false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final StoredTokenPair tokenPair = (StoredTokenPair) o;
        return accessToken.equals(tokenPair.accessToken)
                && refreshToken.equals(tokenPair.refreshToken);
    }

    /**
     * Gets a hash code based on the contents of the {@link StoredTokenPair}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(accessToken, refreshToken);
    }
}
