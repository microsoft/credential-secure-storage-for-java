// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CredManagerBackedTokenStoreTest {

    private CredManagerBackedTokenStore underTest;

    @Before
    public void setup() {
        underTest = new CredManagerBackedTokenStore();
    }

    //low value basic tests that should auto run
    @Test
    public void testCreate() throws Exception {
        final String secretValue = "my secret";
        Token token = underTest.create("do not care", secretValue);

        assertEquals("Secret not correct", secretValue, token.getValue());
    }

    @Test
    public void testGetUsername() throws Exception {
        final Token token = new Token("do not care", TokenType.Personal);
        assertEquals("Username is not correct", CredManagerBackedTokenStore.TOKEN_USERNAME,
                underTest.getUsername(token));
    }

    @Test
    public void testGetCredentialBlob() throws Exception {
        final Token token = new Token("do not care", TokenType.Personal);
        assertEquals("CredentialBlob is not correct", "do not care",
                underTest.getCredentialBlob(token));
    }

}