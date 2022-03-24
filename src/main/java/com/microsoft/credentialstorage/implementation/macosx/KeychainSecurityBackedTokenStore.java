// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

import com.microsoft.credentialstorage.model.StoredTokenType;
import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.model.StoredToken;

import java.util.Map;

/**
 * Keychain store for a token.
 */
public final class KeychainSecurityBackedTokenStore extends KeychainSecurityCliStore implements SecretStore<StoredToken> {

    @Override
    public StoredToken get(final String key) {
        final Map<String, Object> metaData = read(SecretKind.Token, key);

        final StoredToken result;
        if (metaData.size() > 0) {
            final String typeName = (String) metaData.get(ACCOUNT_METADATA);
            final String secret = (String) metaData.get(PASSWORD);

            result = new StoredToken(secret.toCharArray(), StoredTokenType.fromDescription(typeName));
        } else {
            result = null;
        }

        return result;
    }

    @Override
    public boolean add(final String key, final StoredToken token) {
        writeTokenKind(key, SecretKind.Token, token);
        return true;
    }

    @Override
    public boolean delete(final String targetName) {
        return deleteByKind(targetName, SecretKind.Token);
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
