// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.helpers;

import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.function.Function;

public class StringHelperTest {
    @Test
    public void isNullOrWhiteSpace_null() {
        Assert.assertTrue(StringHelper.isNullOrWhiteSpace(null));
    }

    @Test
    public void isNullOrWhiteSpace_empty() {
        Assert.assertTrue(StringHelper.isNullOrWhiteSpace(StringHelper.EMPTY));
    }

    @Test
    public void isNullOrWhiteSpace_whiteSpace() {
        Assert.assertTrue(StringHelper.isNullOrWhiteSpace(" "));
        Assert.assertTrue(StringHelper.isNullOrWhiteSpace("\n"));
        Assert.assertTrue(StringHelper.isNullOrWhiteSpace("\t"));
    }

    @Test
    public void isNullOrWhiteSpace_content() {
        Assert.assertFalse(StringHelper.isNullOrWhiteSpace("isNullOrWhiteSpace"));
        Assert.assertFalse(StringHelper.isNullOrWhiteSpace(" isNullOrWhiteSpace"));
        Assert.assertFalse(StringHelper.isNullOrWhiteSpace("isNullOrWhiteSpace "));
        Assert.assertFalse(StringHelper.isNullOrWhiteSpace(" isNullOrWhiteSpace "));
    }

    @Test
    public void join_typical() {
        final String[] a = {"a", "b", "c"};

        final String actual = StringHelper.join(",", a, 0, a.length, Function.identity());

        Assert.assertEquals("a,b,c", actual);
    }

    @Test
    public void join_edge_oneElementInArray() {
        final String[] a = {"a"};

        final String actual = StringHelper.join(",", a, 0, a.length, Function.identity());

        Assert.assertEquals("a", actual);
    }

    @Test
    public void join_skipFirst() {
        final String[] a = {"a", "b", "c"};

        final String actual = StringHelper.join(",", a, 1, a.length - 1, Function.identity());

        Assert.assertEquals("b,c", actual);
    }

    @Test
    public void join_skipLast() {
        final String[] a = {"a", "b", "c"};

        final String actual = StringHelper.join(",", a, 0, a.length - 1, Function.identity());

        Assert.assertEquals("a,b", actual);
    }

    @Test
    public void join_returnsStringEmptyIfCountZero() {
        final String[] a = {"a", "b", "c"};

        Assert.assertEquals(StringHelper.EMPTY, StringHelper.join(",", a, 0, 0, Function.identity()));
    }

    @Test
    public void join_returnsStringEmptyIfValueHasNoElements() {
        final String[] emptyArray = {};

        Assert.assertEquals(StringHelper.EMPTY, StringHelper.join(",", emptyArray, 0, 0, Function.identity()));
    }

    @Test
    public void join_returnsStringEmptyIfSeparatorAndAllElementsAreEmpty() {
        final String[] arrayOfEmpty = {StringHelper.EMPTY, StringHelper.EMPTY, StringHelper.EMPTY};

        Assert.assertEquals(StringHelper.EMPTY, StringHelper.join(StringHelper.EMPTY, arrayOfEmpty, 0, 3, Function.identity()));
    }

    @Test
    public void join_withQuotingProcessor() {
        final Function<String, String> quotingProcessor = str -> str.contains(" ") ? '"' + str + '"' : str;
        final String[] args = {"--user", "man-with-hat", "--password", "battery horse staple correct"};

        final String actual = StringHelper.join(" ", args, 0, args.length, quotingProcessor);

        Assert.assertEquals("--user man-with-hat --password \"battery horse staple correct\"", actual);
    }

    public static void assertLinesEqual(final String expected, final String actual) throws IOException {
        final StringReader expectedSr = new StringReader(expected);
        final BufferedReader expectedBr = new BufferedReader(expectedSr);
        final StringReader actualSr = new StringReader(actual);
        final BufferedReader actualBr = new BufferedReader(actualSr);

        String expectedLine;
        String actualLine;
        while ((expectedLine = expectedBr.readLine()) != null) {
            if ((actualLine = actualBr.readLine()) != null) {
                Assert.assertEquals(expectedLine, actualLine);
            } else {
                Assert.fail("'expected' contained more lines than 'actual'.");
            }
        }
        if ((actualBr.readLine()) != null) {
            Assert.fail("'actual' contained more lines than 'expected'.");
        }
    }
}
