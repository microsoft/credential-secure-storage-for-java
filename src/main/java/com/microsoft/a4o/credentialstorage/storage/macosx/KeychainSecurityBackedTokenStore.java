// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.secret.Token;

/**
 * Keychain store for a token.
 */
public final class KeychainSecurityBackedTokenStore extends KeychainSecurityCliStore implements SecretStore<Token> {

    @Override
    public Token get(String key) {
        return readToken(key);
    }

    @Override
    public boolean add(String key, Token secret) {
        writeToken(key, secret);
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
