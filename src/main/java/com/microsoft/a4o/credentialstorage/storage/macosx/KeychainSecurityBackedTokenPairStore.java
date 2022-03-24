// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.secret.TokenPair;

public class KeychainSecurityBackedTokenPairStore extends KeychainSecurityCliStore implements SecretStore<TokenPair> {

    @Override
    public TokenPair get(final String key) {
        return readTokenPair(key);
    }

    @Override
    public boolean add(final String key, final TokenPair secret) {
        writeTokenPair(key, secret);
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
