// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a value, which is stored as a char array
 * with a built-in mechanism for securely clearing the value when it's not needed anymore.
 */
final class ClearableValue {
    private static final char[] EMPTY = new char[0];

    private volatile char[] value;

    ClearableValue(final char[] value) {
        Objects.requireNonNull(value, "The value parameter is null");
        this.value = Arrays.copyOf(value, value.length);
    }

    char[] getValue() {
        return value;
    }

    void clear() {
        if (EMPTY == value) {
            return;
        }

        final char[] tempValue = value;
        value = EMPTY;

        Arrays.fill(tempValue, (char) 0x00);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ClearableValue that = (ClearableValue) o;

        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}
