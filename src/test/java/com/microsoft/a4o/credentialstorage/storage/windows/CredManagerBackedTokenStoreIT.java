// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows;

import com.microsoft.a4o.credentialstorage.helpers.SystemHelper;
import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class CredManagerBackedTokenStoreIT {

    private CredManagerBackedTokenStore underTest;

    @Before
    public void setup() {
        assumeTrue(SystemHelper.isWindows());

        underTest = new CredManagerBackedTokenStore();
    }

    @Test
    public void e2eTestStoreReadDelete() {
        final Token token = new Token("do not care", TokenType.PERSONAL);
        final String key = "CredManagerTest:http://test.com:Token";

        // this should have been saved to cred manager, it would be good if you can set a breakpoint
        // and manaully verify this now
        underTest.add(key, token);

        Token readToken = underTest.get(key);

        assertEquals("Retrieved token is different", token.getValue(), readToken.getValue());

        // The token under the specified key should be deleted now, it's a good idea to manually verify this now
        boolean deleted = underTest.delete(key);
        assertTrue("Test token should be deleted", deleted);

        deleted = underTest.delete(key);
        assertFalse("Test token deleted twice, did first delete fail?", deleted);

        readToken = underTest.get(key);
        assertNull("Token can still be read from store?  Did delete fail?", readToken);
    }

}