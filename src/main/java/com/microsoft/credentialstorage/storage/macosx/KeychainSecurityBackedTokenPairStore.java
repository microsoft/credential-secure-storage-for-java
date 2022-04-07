// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.macosx;

import com.microsoft.credentialstorage.storage.SecretStore;
import com.microsoft.credentialstorage.secret.TokenPair;

import java.util.Map;

/**
 * Keychain store for a token pair.
 */
public final class KeychainSecurityBackedTokenPairStore extends KeychainSecurityCliStore implements SecretStore<TokenPair> {

    @Override
    public TokenPair get(final String key) {
        char[] accessToken, refreshToken;

        final Map<String, Object> accessTokenMetaData = read(SecretKind.TokenPair_Access_Token, key);

        if (accessTokenMetaData.size() > 0) {
            accessToken = (char[]) accessTokenMetaData.get(PASSWORD);
        } else {
            accessToken = null;
        }

        final Map<String, Object> refreshTokenMetaData = read(SecretKind.TokenPair_Refresh_Token, key);

        if (refreshTokenMetaData.size() > 0) {
            refreshToken = (char[]) refreshTokenMetaData.get(PASSWORD);
        } else {
            refreshToken = null;
        }

        if (accessToken != null && refreshToken != null) {
            return new TokenPair(accessToken, refreshToken);
        }

        return null;
    }

    @Override
    public boolean add(final String key, final TokenPair tokenPair) {
        if (tokenPair.getAccessToken().getValue() != null) {
            writeTokenKind(key, SecretKind.TokenPair_Access_Token, tokenPair.getAccessToken());
        }

        if (tokenPair.getRefreshToken().getValue() != null) {
            writeTokenKind(key, SecretKind.TokenPair_Refresh_Token, tokenPair.getRefreshToken());
        }
        return true;
    }

    @Override
    public boolean delete(final String targetName) {
        return deleteByKind(targetName, SecretKind.TokenPair_Access_Token)
                && deleteByKind(targetName, SecretKind.TokenPair_Refresh_Token);
    }

    /**
     * Keychain Access is secure
     *
     * @return {@code true} for Keychain Access
     */
    @Override
    public boolean isSecure() {
        return true;
    }
}
