// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

import java.util.Objects;

/**
 * Credential for user authentication.
 */
public final class StoredCredential implements StoredSecret {
    private static final int USERNAME_MAX_LENGTH = 511;
    private static final int PASSWORD_MAX_LENGTH = 2047;

    private final String username;
    private final ClearableValue password;

    /**
     * Creates a credential object with a username and password pair.
     *
     * @param username The username value of the {@link StoredCredential}.
     * @param password The password value of the {@link StoredCredential}.
     */
    public StoredCredential(final String username, final char[] password) {
        Objects.requireNonNull(username, "The username parameter is null");
        if (username.length() > USERNAME_MAX_LENGTH) {
            throw new IllegalArgumentException(String.format("The username parameter cannot " +
                    "be longer than %1$d characters.", USERNAME_MAX_LENGTH));
        }
        this.username = username;

        Objects.requireNonNull(password, "The password parameter is null");
        if (password.length > PASSWORD_MAX_LENGTH) {
            throw new IllegalArgumentException(String.format("The password parameter cannot " +
                    "be longer than %1$d characters.", PASSWORD_MAX_LENGTH));
        }
        this.password = new ClearableValue(password);
    }

    /**
     * Unique identifier of the user.
     * @return username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Secret related to the username.
     * @return secret
     */
    public char[] getPassword() {
        return password.getValue();
    }

    /**
     * Clear the secret value.
     */
    @Override
    public void clear() {
        password.clear();
    }

    /**
     * Compares an object to this {@link StoredCredential} for equality.
     *
     * @param o The object to compare.
     * @return True if equal; false otherwise.
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final StoredCredential that = (StoredCredential) o;
        return username.equals(that.username) && password.equals(that.password);
    }

    /**
     * Gets a hash code based on the contents of the {@link StoredCredential}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(username, password);
    }
}
