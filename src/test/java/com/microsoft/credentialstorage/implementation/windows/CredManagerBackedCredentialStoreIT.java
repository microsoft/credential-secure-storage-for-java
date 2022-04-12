// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

import com.microsoft.credentialstorage.model.StoredCredential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manually verify this now
        underTest.add(key, credential);

        StoredCredential readCred = underTest.get(key);

        assertEquals("Retrieved Credential.Username is different", username, readCred.getUsername());
        assertArrayEquals("Retrieved Credential.Password is different", password, readCred.getPassword());

        // The credential under the specified key should be deleted now, it's a good idea to manually verify this now
        boolean deleted = underTest.delete(key);
        assertTrue("Test credential should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Test credential deleted twice, did first delete fail?", deleted);

        readCred = underTest.get(key);
        assertNull("Cred can still be read from store?  Did delete fail?", readCred);
    }
}