// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage;

import com.microsoft.credentialstorage.model.StoredSecret;

/**
 * Secret store to hold the credentials.
 *
 * @param <E> a secret
 */
public interface SecretStore<E extends StoredSecret> {

    /**
     * Retrieve a secret identified by the key from this store.
     *
     * If there is no secret identified by this key, return {@code null}
     *
     * @param key
     *      for which a secret is associated with
     *
     * @return secret stored by this key, or {@code null}
     */
    E get(final String key);

    /**
     * Remove the secret identified by the key from this store
     *
     * @param key
     *      for which a secret is associated with
     *
     * @return {@code true} if secret is deleted successfully
     *         {@code false} otherwise
     */
    boolean delete(final String key);

    /**
     * Save the secret identified by the key to this store.  Replace existing secret if it exists.
     * @param key
     *      for which a secret is associated with
     * @param secret
     *      secret to be stored
     *
     * @return {@code true} if secret is added successfully
     *         {@code false} otherwise
     */
    boolean add(final String key, final E secret);

    /**
     * Indicate whether this store is secure or not.  Generally a secure storage is password protected, and all
     * data maybe encrypted on disk.  However this method does not assert any of those claims - it simply
     * returns this value as an attribute of the underlying storage
     *
     * @return {@code true} if the underlying storage is considered "secure"
     *         {@code false} otherwise
     */
    boolean isSecure();
}
