// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.windows;

import com.microsoft.credentialstorage.secret.Credential;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CredManagerBackedCredentialStoreTest {

    private CredManagerBackedCredentialStore underTest;
    private final String username = "myusername";
    private final char[] password = "mypassword".toCharArray();

    @Before
    public void setup() throws Exception {
        underTest = new CredManagerBackedCredentialStore();
    }

    //low value basic tests that should auto run
    @Test
    public void testCreate() {
        Credential credential = underTest.create(username, password);

        assertEquals("Username not correct", username, credential.getUsername());
        assertArrayEquals("Password not correct", password, credential.getPassword());
    }
}
