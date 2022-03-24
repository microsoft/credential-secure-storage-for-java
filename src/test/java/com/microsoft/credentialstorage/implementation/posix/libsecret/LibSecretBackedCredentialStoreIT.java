// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.libsecret;

import com.microsoft.credentialstorage.model.StoredCredential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

public class LibSecretBackedCredentialStoreIT {
    LibSecretBackedCredentialStore underTest;

    @Before
    public void setUp() {
        //Only test on platform that has libsecret support
        assumeTrue(LibSecretBackedSecureStore.isSupported());

        underTest = new LibSecretBackedCredentialStore();
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