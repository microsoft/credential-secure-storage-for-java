// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

import java.util.Objects;

/**
 * A security token, usually acquired by some authentication and identity services.
 */
public final class StoredToken implements StoredSecret {
    private final StoredTokenType type;
    private final ClearableValue value;

    /**
     * Creates a token object with a value and the specified type for a target identity.
     *
     * @param value token value
     * @param type token type
     */
    public StoredToken(final char[] value, final StoredTokenType type) {
        Objects.requireNonNull(value, "The value parameter is null");
        Objects.requireNonNull(type, "The type parameter is null");

        this.type = type;
        this.value = new ClearableValue(value);
    }

    /**
     * The type of the security token.
     * @return token type
     */
    public StoredTokenType getType() {
        return type;
    }

    /**
     * The raw contents of the token.
     * @return token value
     */
    public char[] getValue() {
        return value.getValue();
    }

    /**
     * Clear the token value.
     */
    @Override
    public void clear() {
        value.clear();
    }

    /**
     * Compares an object to this {@link StoredToken} for equality.
     *
     * @param o The object to compare.
     * @return True is equal; false otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final StoredToken token = (StoredToken) o;
        return type == token.type && value.equals(token.value);
    }

    /**
     * Gets a hash code based on the contents of the token.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(type, value);
    }
}
