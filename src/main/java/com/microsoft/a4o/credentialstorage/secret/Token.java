// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.secret;

import java.util.Arrays;
import java.util.Objects;

/**
 * A security token, usually acquired by some authentication and identity services.
 */
public final class Token implements Secret {
    private final TokenType type;
    private final char[] value;

    /**
     * Creates a token object with a value and the specified type for a target identity.
     *
     * @param value token value
     * @param type token type
     */
    public Token(final char[] value, final TokenType type) {
        Objects.requireNonNull(value, "The value parameter is null");
        Objects.requireNonNull(type, "The type parameter is null");

        this.type = type;
        this.value = value;
    }

    /**
     * The type of the security token.
     * @return token type
     */
    public TokenType getType() {
        return type;
    }

    /**
     * The raw contents of the token.
     * @return token value
     */
    public char[] getValue() {
        return value;
    }

    /**
     * Compares an object to this {@link Token} for equality.
     *
     * @param o The object to compare.
     * @return True is equal; false otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Token token = (Token) o;
        return type == token.type && Arrays.equals(value, token.value);
    }

    /**
     * Gets a hash code based on the contents of the token.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(type, Arrays.hashCode(value));
    }
}
