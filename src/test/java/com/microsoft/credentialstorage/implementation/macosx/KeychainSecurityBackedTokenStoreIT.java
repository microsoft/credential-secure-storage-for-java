// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class KeychainSecurityBackedTokenStoreIT {

    private KeychainSecurityBackedTokenStore underTest;

    @Before
    public void setup() {
        assumeTrue(KeychainSecurityCliStore.isSupported());

        underTest = new KeychainSecurityBackedTokenStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        StoredToken token = new StoredToken("do not care".toCharArray(), StoredTokenType.PERSONAL);
        String key = "KeychainTest:http://test.com:Token";

        boolean added = underTest.add(key, token);
        assertTrue("Storing token failed", added);

        StoredToken readToken = underTest.get(key);

        assertNotNull("Token not found", readToken);
        assertArrayEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        boolean deleted = underTest.delete(key);
        assertTrue("Deleting token failed", deleted);

        deleted = underTest.delete(key);
        assertFalse("Token deleted twice, did first delete fail?", deleted);

        StoredToken nonExistentToken = underTest.get(key);
        assertNull(nonExistentToken);
    }

    @Test
    public void e2eTestStoreReadDeleteAnotherAccount() {
        String key = "KeychainTest:http://test.com:Token";

        StoredToken token1 = new StoredToken("do not care".toCharArray(), StoredTokenType.PERSONAL);
        boolean added1 = underTest.add(key, token1);
        assertTrue("Storing token1 failed", added1);

        StoredToken readToken1 = underTest.get(key);

        assertNotNull("Token not found", readToken1);
        assertArrayEquals("Retrieved token is different", token1.getValue(), readToken1.getValue());

        StoredToken token2 = new StoredToken("do not care completely".toCharArray(), StoredTokenType.ACCESS);
        boolean added2 = underTest.add(key, token2);
        assertTrue("Storing token2 failed", added2);

        StoredToken readToken2 = underTest.get(key);

        assertNotNull("Token not found", readToken2);
        assertArrayEquals("Retrieved token is different", token2.getValue(), readToken2.getValue());

        boolean deleted = underTest.delete(key);
        assertTrue("Deleting token failed", deleted);

        StoredToken nonExistentToken = underTest.get(key);
        assertNull(nonExistentToken);
    }
}