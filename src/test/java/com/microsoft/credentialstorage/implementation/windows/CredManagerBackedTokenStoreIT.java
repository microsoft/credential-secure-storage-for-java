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

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manually verify this now
        underTest.add(key, token);

        StoredToken readToken = underTest.get(key);

        assertNotNull("Token not found", readToken);
        assertArrayEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        // The token under the specified key should be deleted now, it's a good idea to manually verify this now
        boolean deleted = underTest.delete(key);
        assertTrue("Test token should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Test token deleted twice, did first delete fail?", deleted);

        readToken = underTest.get(key);
        assertNull("Token can still be read from store? Did delete fail?", readToken);
    }

}