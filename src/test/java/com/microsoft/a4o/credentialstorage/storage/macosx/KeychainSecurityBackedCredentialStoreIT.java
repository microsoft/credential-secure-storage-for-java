// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.secret.Credential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;

public class KeychainSecurityBackedCredentialStoreIT {

    private KeychainSecurityBackedCredentialStore underTest;
    private final String username = "myusername";
    private final char[] password = "mypassword".toCharArray();

    @Before
    public void setUp() throws Exception {
        assumeTrue(KeychainSecurityCliStore.isSupported());

        underTest = new KeychainSecurityBackedCredentialStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        Credential credential= new Credential(username, password);
        final String key = "KeychainTest:http://test.com:Credential";

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manually verify this now
        underTest.add(key, credential);

        final Credential readCred = underTest.get(key);

        assertEquals("Retrieved Credential.Username is different", username, credential.getUsername());
        assertEquals("Retrieved Credential.Password is different", password, credential.getPassword());

        // The credential under the specified key should be deleted now
        underTest.delete(key);

        final Credential nonExistent = underTest.get(key);
        assertNull(nonExistent);
    }
}
