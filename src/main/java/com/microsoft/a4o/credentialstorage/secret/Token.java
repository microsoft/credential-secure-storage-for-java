// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.secret;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;

import java.util.Objects;
import java.util.UUID;

/**
 * A security token, usually acquired by some authentication and identity services.
 */
public final class Token implements Secret {
    private static final UUID EMPTY_UUID = new UUID(0, 0);

    private final TokenType type;
    private final String value;
    private final UUID targetIdentity;

    /**
     * Creates a token object with a value and the specified type for a target identity.
     *
     * @param value token value
     * @param type token type
     * @param targetIdentity token target identity
     */
    public Token(final String value, final TokenType type, final UUID targetIdentity) {
        if (StringHelper.isNullOrWhiteSpace(value)) {
            throw new IllegalArgumentException("The value parameter is null or invalid");
        }
        Objects.requireNonNull(type, "The type parameter is null");
        Objects.requireNonNull(targetIdentity, "The targetIdentity parameter is null");

        this.type = type;
        this.value = value;
        this.targetIdentity = targetIdentity;
    }

    /**
     * Creates a token object with a value and the specified type with zero UUID as a target identity.
     *
     * @param value token value
     * @param type token type
     */
    public Token(final String value, final TokenType type) {
        this(value, type, EMPTY_UUID);
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
    public String getValue() {
        return value;
    }

    /**
     * The target identity for the security token.
     * @return token target identity
     */
    public UUID getTargetIdentity() {
        return targetIdentity;
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
        return type == token.type && value.equals(token.value) && targetIdentity.equals(token.targetIdentity);
    }

    /**
     * Gets a hash code based on the contents of the token.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(type, value, targetIdentity);
    }
}
