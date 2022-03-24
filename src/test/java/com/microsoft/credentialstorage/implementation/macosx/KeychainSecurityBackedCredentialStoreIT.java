// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

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

public class KeychainSecurityBackedCredentialStoreIT {

    private KeychainSecurityBackedCredentialStore underTest;
    private final String username = "myusername";
    private final char[] password = "mypassword".toCharArray();

    @Before
    public void setUp() {
        assumeTrue(KeychainSecurityCliStore.isSupported());

        underTest = new KeychainSecurityBackedCredentialStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        StoredCredential credential = new StoredCredential(username, password);
        final String key = "KeychainTest:http://test.com:Credential";

        boolean success = underTest.add(key, credential);
        assertTrue("Storing credential failed", success);

        final StoredCredential readCred = underTest.get(key);

        assertNotNull("Credential not found", readCred);
        assertEquals("Retrieved Credential.Username is different", username, readCred.getUsername());
        assertArrayEquals("Retrieved Credential.Password is different", password, readCred.getPassword());

        boolean deleted = underTest.delete(key);
        assertTrue("Test credential should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Test credential deleted twice, did first delete fail?", deleted);

        final StoredCredential nonExistent = underTest.get(key);
        assertNull("Credential can still be read from store", nonExistent);
    }

    @Test
    public void e2eTestStoreReadDeleteAnotherAccount() {
        final String key = "KeychainTest:http://test.com:Credential";

        StoredCredential credential1 = new StoredCredential("username1", "password1".toCharArray());
        boolean success1 = underTest.add(key, credential1);
        assertTrue("Storing credential failed", success1);

        final StoredCredential readCred1 = underTest.get(key);

        assertNotNull("Credential not found", readCred1);
        assertEquals("Retrieved Credential.Username is different", "username1", readCred1.getUsername());
        assertArrayEquals("Retrieved Credential.Password is different", "password1".toCharArray(), readCred1.getPassword());

        StoredCredential credential2 = new StoredCredential("username2", "password2".toCharArray());
        boolean success2 = underTest.add(key, credential2);
        assertTrue("Storing credential failed", success2);

        final StoredCredential readCred2 = underTest.get(key);

        assertNotNull("Credential not found", readCred2);
        assertEquals("Retrieved Credential.Username is different", "username2", readCred2.getUsername());
        assertArrayEquals("Retrieved Credential.Password is different", "password2".toCharArray(), readCred2.getPassword());

        boolean deleted = underTest.delete(key);
        assertTrue("Test credential should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Test credential deleted twice, did first delete fail?", deleted);

        final StoredCredential nonExistent = underTest.get(key);
        assertNull("Credential can still be read from store", nonExistent);
    }
}
