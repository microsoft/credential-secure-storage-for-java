// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

/**
 * Represents a type of security token.
 */
public enum TokenType {
    /**
     * Unknown type.
     */
    UNKNOWN(null),
    /**
     * Access Token
     */
    ACCESS("Access Token"),
    /**
     * Refresh Token
     */
    REFRESH("Refresh Token"),
    /**
     * Personal Access Token, can be compact or not.
     */
    PERSONAL("Personal Access Token"),
    /**
     * Federated Authentication (aka FedAuth) Token
     */
    FEDERATED("Federated Authentication Token"),
    /**
     * Used only for testing
     */
    TEST("Test-only Token");

    private final String description;

    TokenType(final String description) {
        this.description = description;
    }

    /**
     * Returns token description.
     * @return description
     */
    public String getDescription() {
        return description;
    }
}
