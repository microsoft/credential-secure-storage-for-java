// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

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

public class CredManagerBackedCredentialStoreIT {

    private CredManagerBackedCredentialStore underTest;
    private final String username = "myusername";
    private final char[] password = "mypassword".toCharArray();

    @Before
    public void setup() throws Exception {
        assumeTrue(CredManagerBackedSecureStore.isSupported());

        underTest = new CredManagerBackedCredentialStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        StoredCredential credential= new StoredCredential(username, password);
        final String key = "CredManagerTest:http://test.com:Credential";

        boolean added = underTest.add(key, credential);
        assertTrue("Storing credential failed", added);

        StoredCredential readCred = underTest.get(key);

        assertNotNull("Credential not found", readCred);
        assertEquals("Retrieved Credential.Username is different", username, readCred.getUsername());
        assertArrayEquals("Retrieved Credential.Password is different", password, readCred.getPassword());

        // The credential under the specified key should be deleted now, it's a good idea to manually verify this now
        boolean deleted = underTest.delete(key);
        assertTrue("Credential not deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Credential deleted twice, did first delete fail?", deleted);

        final StoredCredential nonExistent = underTest.get(key);
        assertNull("Credential can still be read from store", nonExistent);
    }
}