// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.secret;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;

import java.util.Objects;

/**
 * Credential for user authentication.
 */
public final class Credential implements Secret {
    private final String username;
    private final String password;

    /**
     * Creates a credential object with a username and password pair.
     *
     * @param username The username value of the {@link Credential}.
     * @param password The password value of the {@link Credential}.
     */
    public Credential(final String username, final String password) {
        this.username = Objects.requireNonNullElse(username, StringHelper.Empty);
        this.password = Objects.requireNonNullElse(password, StringHelper.Empty);
    }

    /**
     * Creates a credential object with only a username.
     *
     * @param username The username value of the {@link Credential}.
     */
    public Credential(final String username) {
        this(username, StringHelper.Empty);
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
    public String getPassword() {
        return password;
    }

    /**
     * Compares an object to this {@link Credential} for equality.
     *
     * @param obj The object to compare.
     * @return True if equal; false otherwise.
     */
    @Override
    public boolean equals(final Object obj) {
        return operatorEquals(this, obj instanceof Credential ? ((Credential) obj) : null);
    }

    /**
     * Gets a hash code based on the contents of the {@link Credential}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return username.hashCode() + 7 * password.hashCode();
    }

    /**
     * Compares two credentials for equality.
     *
     * @param credential1 Credential to compare.
     * @param credential2 Credential to compare.
     * @return True if equal; false otherwise.
     */
    public static boolean operatorEquals(final Credential credential1, final Credential credential2) {
        if (credential1 == credential2)
            return true;
        if ((credential1 == null) || (null == credential2))
            return false;

        return credential1.username.equals(credential2.username)
                && credential1.password.equals(credential2.password);
    }
}
