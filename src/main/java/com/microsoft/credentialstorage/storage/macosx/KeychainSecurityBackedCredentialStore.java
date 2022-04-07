// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.macosx;

import com.microsoft.credentialstorage.storage.SecretStore;
import com.microsoft.credentialstorage.secret.Credential;

import java.util.Map;

/**
 * Keychain store for a credential.
 */
public final class KeychainSecurityBackedCredentialStore extends KeychainSecurityCliStore
        implements SecretStore<Credential> {

    @Override
    public Credential get(final String key) {
        final Map<String, Object> metaData = read(SecretKind.Credential, key);

        final Credential result;
        if (metaData.size() > 0) {
            final String userName = (String) metaData.get(ACCOUNT_METADATA);
            final String password = (String) metaData.get(PASSWORD);

            result = new Credential(userName, password.toCharArray());
        } else {
            result = null;
        }

        return result;
    }

    @Override
    public boolean add(final String key, final Credential credentials) {
        write(SecretKind.Credential, key, credentials.getUsername(), credentials.getPassword());
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
