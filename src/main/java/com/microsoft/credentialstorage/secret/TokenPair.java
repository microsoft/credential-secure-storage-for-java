// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.secret;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * A security token pair, combining access and refresh tokens.
 */
public final class TokenPair implements Secret {
    private final Token accessToken;
    private final Token refreshToken;

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public TokenPair(final Token accessToken, final Token refreshToken) {
        Objects.requireNonNull(accessToken, "The accessToken parameter is null");
        Objects.requireNonNull(refreshToken, "The refreshToken parameter is null");

        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     * @param parameters Map with additional parameters for the token pair
     */
    public TokenPair(final char[] accessToken, final char[] refreshToken, final Map<String, String> parameters) {
        Objects.requireNonNull(accessToken, "The accessToken parameter is null");
        Objects.requireNonNull(refreshToken, "The refreshToken parameter is null");
        Objects.requireNonNull(parameters, "The parameters parameter is null");

        this.accessToken = new Token(accessToken, TokenType.ACCESS);
        this.refreshToken = new Token(refreshToken, TokenType.REFRESH);
    }

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public TokenPair(final char[] accessToken, final char[] refreshToken) {
        this(accessToken, refreshToken, Collections.emptyMap());
    }

    /**
     * Access token, used to grant access to resources.
     * @return access token
     */
    public Token getAccessToken() {
        return accessToken;
    }

    /**
     * Refresh token, used to grant new access tokens.
     * @return refresh token
     */
    public Token getRefreshToken() {
        return refreshToken;
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
        TokenPair tokenPair = (TokenPair) o;
        return accessToken.equals(tokenPair.accessToken)
                && refreshToken.equals(tokenPair.refreshToken);
    }

    /**
     * Gets a hash code based on the contents of the {@link TokenPair}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(accessToken, refreshToken);
    }
}
