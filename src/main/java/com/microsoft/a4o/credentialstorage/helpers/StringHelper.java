// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.helpers;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Function;

public final class StringHelper {
    public static final String Empty = "";

    private static final Charset UTF8 = StandardCharsets.UTF_8;

    private static final Charset UTF16LE = StandardCharsets.UTF_16LE;

    private StringHelper() {
    }

    public static boolean isNullOrWhiteSpace(final String s) {
        return null == s || (s.trim().length() == 0);
    }

    /**
     * Concatenates the specified elements of a string array,
     * using the specified separator between each element.
     *
     * @param separator  The string to use as a separator.
     *                   separator is included in the returned string only if value has more than one element.
     * @param value      An array that contains the elements to concatenate.
     * @param startIndex The first element in value to use.
     * @param count      The number of elements of value to use.
     * @param processor  A callback that gets to intercept and modify elements before they are inserted.
     * @return A string that consists of the strings in value delimited by the separator string.
     * -or-
     * {@link StringHelper#Empty} if count is zero, value has no elements,
     * or separator and all the elements of value are {@link StringHelper#Empty}.
     */
    public static String join(final String separator, final String[] value, final int startIndex, final int count,
                              final Function<String, String> processor) {
        if (value == null)
            throw new IllegalArgumentException("value is null");
        if (startIndex < 0)
            throw new IllegalArgumentException("startIndex is less than 0");
        if (count < 0)
            throw new IllegalArgumentException("count is less than 0");
        if (startIndex + count > value.length)
            throw new IllegalArgumentException("startIndex + count is greater than the number of elements in value");

        // "If separator is null, an empty string ( String.Empty) is used instead."
        final String sep = Objects.requireNonNullElse(separator, StringHelper.Empty);

        final StringBuilder result = new StringBuilder();

        if (value.length > 0 && count > 0) {
            String element = Objects.requireNonNullElse(value[startIndex], StringHelper.Empty);
            if (processor != null) {
                element = processor.apply(element);
            }
            result.append(element);
            for (int i = startIndex + 1; i < startIndex + count; i++) {
                result.append(sep);
                element = Objects.requireNonNullElse(value[i], StringHelper.Empty);
                if (processor != null) {
                    element = processor.apply(element);
                }
                result.append(element);
            }
        }

        return result.toString();
    }

    /**
     * Encodes all the characters in the specified string into a sequence of UTF-8 bytes.
     *
     * @param value The string containing the characters to encode.
     * @return A byte array containing the results of encoding the specified set of characters.
     */
    public static byte[] UTF8GetBytes(final String value) {
        return value.getBytes(UTF8);
    }

    /**
     * Encodes all the characters in the specified string into a sequence of UTF-16LE bytes.
     *
     * @param value The string containing the characters to encode.
     * @return A byte array containing the results of encoding the specified set of characters.
     */
    public static byte[] UTF16LEGetBytes(final String value) {
        return value.getBytes(UTF16LE);
    }

    /**
     * Decodes all the bytes in the specified byte array into a string.
     *
     * @param bytes The byte array containing the sequence of bytes to decode.
     * @return A string that contains the results of decoding the specified sequence of bytes.
     */
    public static String UTF16LEGetString(final byte[] bytes) {
        return new String(bytes, UTF16LE);
    }
}