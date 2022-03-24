// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

import com.microsoft.credentialstorage.model.StoredToken;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class CredManagerBackedTokenStoreTest {

    private CredManagerBackedTokenStore underTest;

    @Before
    public void setup() {
        underTest = new CredManagerBackedTokenStore();
    }

    //low value basic tests that should auto run
    @Test
    public void testCreate() {
        char[] secretValue = "my secret".toCharArray();

        StoredToken token = underTest.create("do not care", secretValue);

        assertArrayEquals("Secret not correct", secretValue, token.getValue());
    }
}