// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.secret.Credential;

/**
 * Keychain store for a credential.
 */
public final class KeychainSecurityBackedCredentialStore extends KeychainSecurityCliStore
        implements SecretStore<Credential> {

    @Override
    public Credential get(String key) {
        return readCredentials(key);
    }

    @Override
    public boolean add(String key, Credential secret) {
        writeCredential(key, secret);
        return true;
    }

    @Override
    public boolean delete(final String targetName) {
        return deleteByKind(targetName, SecretKind.Credential);
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
