// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.model.StoredTokenPair;

import java.util.Map;

/**
 * Keychain store for a token pair.
 */
public final class KeychainSecurityBackedTokenPairStore extends KeychainSecurityCliStore implements SecretStore<StoredTokenPair> {

    @Override
    public StoredTokenPair get(final String key) {
        char[] accessToken, refreshToken;

        final Map<String, Object> accessTokenMetaData = read(SecretKind.TokenPair_Access_Token, key);

        if (accessTokenMetaData.size() > 0) {
            accessToken = ((String) accessTokenMetaData.get(PASSWORD)).toCharArray();
        } else {
            accessToken = null;
        }

        final Map<String, Object> refreshTokenMetaData = read(SecretKind.TokenPair_Refresh_Token, key);

        if (refreshTokenMetaData.size() > 0) {
            refreshToken = ((String) refreshTokenMetaData.get(PASSWORD)).toCharArray();
        } else {
            refreshToken = null;
        }

        if (accessToken != null && refreshToken != null) {
            return new StoredTokenPair(accessToken, refreshToken);
        }

        return null;
    }

    @Override
    public boolean add(final String key, final StoredTokenPair tokenPair) {
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
