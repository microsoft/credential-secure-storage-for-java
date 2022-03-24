// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

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

public class CredManagerBackedTokenStoreIT {

    private CredManagerBackedTokenStore underTest;

    @Before
    public void setup() {
        assumeTrue(CredManagerBackedSecureStore.isSupported());

        underTest = new CredManagerBackedTokenStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        final StoredToken token = new StoredToken("do not care".toCharArray(), StoredTokenType.PERSONAL);
        final String key = "CredManagerTest:http://test.com:Token";

        boolean added = underTest.add(key, token);
        assertTrue("Storing token failed", added);

        StoredToken readToken = underTest.get(key);

        assertNotNull("Token not found", readToken);
        assertArrayEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        boolean deleted = underTest.delete(key);
        assertTrue("Token should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Token deleted twice, did first delete fail?", deleted);

        final StoredToken nonExistent = underTest.get(key);
        assertNull("Token can still be read from store", nonExistent);
    }
}