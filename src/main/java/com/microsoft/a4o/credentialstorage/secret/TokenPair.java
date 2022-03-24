// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.secret;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;

import java.util.Collections;
import java.util.Map;

public class TokenPair implements Secret {
    private final Token accessToken;
    private final Token refreshToken;
    private final Map<String, String> parameters;

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public TokenPair(final String accessToken, final String refreshToken) {
        if (StringHelper.isNullOrWhiteSpace(accessToken)) {
            throw new IllegalArgumentException("The accessToken parameter is null or invalid.");
        }
        if (StringHelper.isNullOrWhiteSpace(refreshToken)) {
            throw new IllegalArgumentException("The refreshToken parameter is null or invalid.");
        }

        this.accessToken = new Token(accessToken, TokenType.Access);
        this.refreshToken = new Token(refreshToken, TokenType.Refresh);
        this.parameters = Collections.emptyMap();
    }

    /**
     * Access token, used to grant access to resources.
     */
    public Token getAccessToken() {
        return accessToken;
    }

    /**
     * Refresh token, used to grant new access tokens.
     */
    public Token getRefreshToken() {
        return refreshToken;
    }

    /**
     * Additional token parameters.
     */
    public Map<String, String> getParameters() {
        return parameters;
    }

    /**
     * Compares an object to this.
     *
     * @param object The object to compare.
     * @return True if equal; false otherwise
     */
    @Override
    public boolean equals(final Object object) {
        return operatorEquals(this, object instanceof TokenPair ? ((TokenPair) object) : null);
    }

    /**
     * Gets a hash code based on the contents of the {@link TokenPair}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return accessToken.hashCode() * refreshToken.hashCode();
    }

    /**
     * Compares two {@link TokenPair} for equality.
     *
     * @param pair1 {@link TokenPair} to compare.
     * @param pair2 {@link TokenPair} to compare.
     * @return True if equal; false otherwise.
     */
    public static boolean operatorEquals(final TokenPair pair1, final TokenPair pair2) {
        if (pair1 == pair2)
            return true;
        if ((pair1 == null) || (null == pair2))
            return false;

        return Token.operatorEquals(pair1.accessToken, pair2.accessToken)
                && Token.operatorEquals(pair1.refreshToken, pair2.refreshToken);
    }
}
