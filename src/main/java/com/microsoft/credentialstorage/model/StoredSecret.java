// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

/**
 * An interface representing a secret.
 */
public interface StoredSecret {
    /**
     * Clear the secret value.
     */
    void clear();
}
