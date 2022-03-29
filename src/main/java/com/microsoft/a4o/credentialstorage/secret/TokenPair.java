// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.secret;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * A security token pair, combining access and refresh tokens.
 */
public final class TokenPair implements Secret {
    private final Token accessToken;
    private final Token refreshToken;
    private final Map<String, String> parameters;

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     * @param parameters Map with additional parameters for the token pair
     */
    public TokenPair(final String accessToken, final String refreshToken, final Map<String, String> parameters) {
        if (StringHelper.isNullOrWhiteSpace(accessToken)) {
            throw new IllegalArgumentException("The accessToken parameter is null or invalid.");
        }
        if (StringHelper.isNullOrWhiteSpace(refreshToken)) {
            throw new IllegalArgumentException("The refreshToken parameter is null or invalid.");
        }
        Objects.requireNonNull(parameters, "The parameters parameter is null");

        this.accessToken = new Token(accessToken, TokenType.ACCESS);
        this.refreshToken = new Token(refreshToken, TokenType.REFRESH);
        this.parameters = Map.copyOf(parameters);
    }

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public TokenPair(final String accessToken, final String refreshToken) {
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
     * Additional token parameters.
     * @return token additional parameters
     */
    public Map<String, String> getParameters() {
        return parameters;
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
                && refreshToken.equals(tokenPair.refreshToken)
                && parameters.equals(tokenPair.parameters);
    }

    /**
     * Gets a hash code based on the contents of the {@link TokenPair}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(accessToken, refreshToken, parameters);
    }
}
