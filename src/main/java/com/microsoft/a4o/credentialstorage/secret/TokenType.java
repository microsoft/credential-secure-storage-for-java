// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.secret;

public enum TokenType {
    Unknown(null),
    /**
     * Access Token
     */
    Access("Access Token"),
    /**
     * Refresh Token
     */
    Refresh("Refresh Token"),
    /**
     * Personal Access Token, can be compact or not.
     */
    Personal("Personal Access Token"),
    /**
     * Federated Authentication (aka FedAuth) Token
     */
    Federated("Federated Authentication Token"),
    /**
     * Used only for testing
     */
    Test("Test-only Token");

    private final String description;

    TokenType(final String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
