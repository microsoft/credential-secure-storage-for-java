// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix.keyring;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringBackedTokenStoreIT {

    GnomeKeyringBackedTokenStore underTest;

    @Before
    public void setUp() throws Exception {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isGnomeKeyringSupported());

        underTest = new GnomeKeyringBackedTokenStore();
    }

    @Test
    public void saveToken() {
        final String testKey = "http://thisisatestkey";

        final Token token = new Token("bi4295xkwev6djxej7hpffuoo4rzcqcogakubpu2sd7kopuoquaq", TokenType.Personal);
        boolean added = underTest.add(testKey, token);

        assertTrue(added);

        final Token readValue = underTest.get(testKey);

        assertEquals(token.getValue(), readValue.getValue());

        boolean deleted = underTest.delete(testKey);
        assertTrue(deleted);

        final Token nonExistent = underTest.get(testKey);
        assertNull(nonExistent);
    }
}