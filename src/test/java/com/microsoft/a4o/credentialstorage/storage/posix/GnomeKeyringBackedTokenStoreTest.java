// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import org.junit.Before;
import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class GnomeKeyringBackedTokenStoreTest {

    GnomeKeyringBackedTokenStore underTest;

    @Before
    public void setUp() throws Exception {
        underTest = new GnomeKeyringBackedTokenStore();
    }

    @Test
    public void serializeDeserialize() {
        final Token token = new Token(UUID.randomUUID().toString(), TokenType.Personal);
        final String serialized = underTest.serialize(token);
        final Token processed = underTest.deserialize(serialized) ;

        assertEquals(token.getValue(), processed.getValue());
    }

}