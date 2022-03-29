// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.macosx;

import com.microsoft.a4o.credentialstorage.helpers.SystemHelper;
import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;

public class KeychainSecurityBackedTokenStoreIT {

    private KeychainSecurityBackedTokenStore underTest;

    @Before
    public void setup() {
        assumeTrue(SystemHelper.isMac());

        underTest = new KeychainSecurityBackedTokenStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        final Token token = new Token("do not care", TokenType.PERSONAL);
        final String key = "KeychainTest:http://test.com:Token";

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manaully verify this now
        underTest.add(key, token);

        final Token readToken = underTest.get(key);

        assertEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        // The credential under the specified key should be deleted now
        underTest.delete(key);

        final Token nonExistentToken = underTest.get(key);
        assertNull(nonExistentToken);
    }
}