// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix.keyring;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;

/**
 * GNOME Keyring store for a token.
 */
public final class GnomeKeyringBackedTokenStore extends GnomeKeyringBackedSecureStore<Token> {

    @Override
    protected Token deserialize(final String secret) {
        return new Token(secret, TokenType.PERSONAL);
    }

    @Override
    protected String serialize(final Token secret) {
        return secret.getValue();
    }

    @Override
    protected String getType() {
        return "PersonalAccessToken";
    }
}
