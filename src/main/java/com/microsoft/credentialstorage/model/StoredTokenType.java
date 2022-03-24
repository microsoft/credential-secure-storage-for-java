// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a type of security token.
 */
public enum StoredTokenType {
    /**
     * Unknown type.
     */
    UNKNOWN("Unknown"),
    /**
     * OAuth2 Access Token
     */
    ACCESS("Access Token"),
    /**
     * OAuth2 Refresh Token
     */
    REFRESH("Refresh Token"),
    /**
     * Personal Access Token.
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

    private static final Map<String, StoredTokenType> VALUE_MAP;

    private final String description;

    static {
        final Map<String, StoredTokenType> valueMap = new HashMap<>();
        for (StoredTokenType storedTokenType : values()) {
            valueMap.put(storedTokenType.getDescription(), storedTokenType);
        }

        VALUE_MAP = Collections.unmodifiableMap(valueMap);
    }

    StoredTokenType(final String description) {
        this.description = description;
    }

    /**
     * Returns enum corresponding to the specified description.
     * @param description to find
     * @return token type
     */
    public static StoredTokenType fromDescription(final String description) {
        return VALUE_MAP.getOrDefault(description, PERSONAL);
    }

    /**
     * Returns token description.
     * @return description
     */
    public String getDescription() {
        return description;
    }
}
