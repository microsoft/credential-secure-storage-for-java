// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.keyring;

import com.microsoft.credentialstorage.model.StoredCredential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringBackedCredentialStoreIT {
    GnomeKeyringBackedCredentialStore underTest;

    @Before
    public void setUp() {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isSupported());

        underTest = new GnomeKeyringBackedCredentialStore();
    }

    @Test
    public void saveCredential() {
        final String key = "http://thisisatestkey";

        final StoredCredential credential = new StoredCredential("username", "pass:\"word".toCharArray());

        boolean added = underTest.add(key, credential);
        assertTrue("Storing credential failed", added);

        final StoredCredential readCred = underTest.get(key);

        assertNotNull("Credential not found", readCred);
        assertEquals(credential.getUsername(), readCred.getUsername());
        assertArrayEquals(credential.getPassword(), readCred.getPassword());

        boolean deleted = underTest.delete(key);
        assertTrue("Credential not deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Credential deleted twice, did first delete fail?", deleted);

        final StoredCredential nonExistent = underTest.get(key);
        assertNull("Credential can still be read from store", nonExistent);
    }
}