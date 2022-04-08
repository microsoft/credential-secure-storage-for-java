// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.macosx;

import com.microsoft.credentialstorage.model.StoredToken;
import com.microsoft.credentialstorage.model.StoredTokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
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
        final StoredToken token = new StoredToken("do not care".toCharArray(), StoredTokenType.PERSONAL);
        final String key = "KeychainTest:http://test.com:Token";

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manaully verify this now
        underTest.add(key, token);

        final StoredToken readToken = underTest.get(key);

        assertEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        // The credential under the specified key should be deleted now
        underTest.delete(key);

        final StoredToken nonExistentToken = underTest.get(key);
        assertNull(nonExistentToken);
    }
}