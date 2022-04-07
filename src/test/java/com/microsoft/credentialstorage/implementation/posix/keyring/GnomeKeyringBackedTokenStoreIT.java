// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringBackedTokenStoreIT {

    GnomeKeyringBackedTokenStore underTest;

    @Before
    public void setUp() throws Exception {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isSupported());

        underTest = new GnomeKeyringBackedTokenStore();
    }

    @Test
    public void saveToken() {
        final String testKey = "http://thisisatestkey";

        final StoredToken token = new StoredToken("bi4295xkwev6djxej7hpffuoo4rzcqcogakubpu2sd7kopuoquaq".toCharArray(), StoredTokenType.PERSONAL);
        boolean added = underTest.add(testKey, token);

        assertTrue(added);

        final StoredToken readValue = underTest.get(testKey);

        assertNotNull(readValue);
        assertArrayEquals(token.getValue(), readValue.getValue());

        boolean deleted = underTest.delete(testKey);
        assertTrue(deleted);

        final StoredToken nonExistent = underTest.get(testKey);
        assertNull(nonExistent);
    }
}