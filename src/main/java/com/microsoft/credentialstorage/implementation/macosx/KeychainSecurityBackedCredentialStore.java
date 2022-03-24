// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.model.StoredCredential;

import java.util.Map;

/**
 * Keychain store for a credential.
 */
public final class KeychainSecurityBackedCredentialStore extends KeychainSecurityCliStore
        implements SecretStore<StoredCredential> {

    @Override
    public StoredCredential get(final String key) {
        final Map<String, Object> metaData = read(SecretKind.Credential, key);

        final StoredCredential result;
        if (!metaData.isEmpty()) {
            final String userName = (String) metaData.get(ACCOUNT_METADATA);
            final String password = (String) metaData.get(PASSWORD);

            result = new StoredCredential(userName, password.toCharArray());
        } else {
            result = null;
        }

        return result;
    }

    @Override
    public boolean add(final String key, final StoredCredential credentials) {
        // if there is existing keychain entry with another account name, delete it.
        final Map<String, Object> metaData = read(SecretKind.Credential, key);
        if (!metaData.isEmpty() && !credentials.getUsername().equals(metaData.get(ACCOUNT_METADATA))) {
            deleteByKind(key, SecretKind.Credential);
        }

        write(SecretKind.Credential, key, credentials.getUsername(), credentials.getPassword());
        return true;
    }

    @Override
    public boolean delete(final String key) {
        return deleteByKind(key, SecretKind.Credential);
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
