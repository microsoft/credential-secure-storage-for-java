// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.secret.TokenType;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.secret.Token;

import java.util.Map;

/**
 * Keychain store for a token.
 */
public final class KeychainSecurityBackedTokenStore extends KeychainSecurityCliStore implements SecretStore<Token> {

    @Override
    public Token get(final String key) {
        final Map<String, Object> metaData = read(SecretKind.Token, key);

        final Token result;
        if (metaData.size() > 0) {
            final String typeName = (String) metaData.get(ACCOUNT_METADATA);
            final char[] password = (char[]) metaData.get(PASSWORD);

            result = new Token(password, TokenType.valueOf(typeName));
        } else {
            result = null;
        }

        return result;
    }

    @Override
    public boolean add(final String key, final Token token) {
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
