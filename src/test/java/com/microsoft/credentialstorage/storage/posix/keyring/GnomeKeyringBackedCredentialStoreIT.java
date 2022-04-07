// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.posix.keyring;

import com.microsoft.credentialstorage.secret.Credential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringBackedCredentialStoreIT {

    GnomeKeyringBackedCredentialStore underTest;

    @Before
    public void setUp() throws Exception {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isSupported());

        underTest = new GnomeKeyringBackedCredentialStore();
    }

    @Test
    public void saveCredential() {
        final String testKey = "http://thisisatestkey";

        final Credential credential = new Credential("username", "pass:\"word".toCharArray());
        boolean added = underTest.add(testKey, credential);

        assertTrue(added);

        final Credential readValue = underTest.get(testKey);

        assertEquals(credential.getUsername(), readValue.getUsername());
        assertEquals(credential.getPassword(), readValue.getPassword());

        boolean deleted = underTest.delete(testKey);
        assertTrue(deleted);

        final Credential nonExistent = underTest.get(testKey);
        assertNull(nonExistent);
    }
}