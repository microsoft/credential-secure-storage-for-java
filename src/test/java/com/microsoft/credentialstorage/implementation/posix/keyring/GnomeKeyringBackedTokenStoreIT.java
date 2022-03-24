// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringBackedTokenStoreIT {
    GnomeKeyringBackedTokenStore underTest;

    @Before
    public void setUp() {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isSupported());

        underTest = new GnomeKeyringBackedTokenStore();
    }

    @Test
    public void saveToken() {
        final String key = "http://thisisatestkey";

        final StoredToken token = new StoredToken("bi4295xkwev6djxej7hpffuoo4rzcqcogakubpu2sd7kopuoquaq".toCharArray(), StoredTokenType.PERSONAL);

        boolean added = underTest.add(key, token);
        assertTrue("Storing token failed", added);

        StoredToken readToken = underTest.get(key);

        assertNotNull("Token not found", readToken);
        assertArrayEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        boolean deleted = underTest.delete(key);
        assertTrue("Token should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Token deleted twice, did first delete fail?", deleted);

        final StoredToken nonExistent = underTest.get(key);
        assertNull(nonExistent);
    }
}