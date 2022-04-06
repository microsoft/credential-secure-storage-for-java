// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;

import java.util.Objects;

/**
 * Credential Manager store for a token.
 */
public final class CredManagerBackedTokenStore extends CredManagerBackedSecureStore<Token> {
    static final String TOKEN_USERNAME = "PersonalAccessToken";

    @Override
    protected Token create(final String username, final char[] secret) {
        return new Token(secret, TokenType.PERSONAL);
    }

    @Override
    public boolean add(final String key, final Token secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "secret cannot be null");

        logger.info("Adding secret for {}", key);

        return writeSecret(key, TOKEN_USERNAME, secret.getValue());
    }
}
