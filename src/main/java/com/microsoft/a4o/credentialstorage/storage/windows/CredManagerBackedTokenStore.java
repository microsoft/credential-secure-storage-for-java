// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows;

import com.microsoft.a4o.credentialstorage.secret.Token;
import com.microsoft.a4o.credentialstorage.secret.TokenType;
import com.microsoft.a4o.credentialstorage.storage.windows.internal.CredManagerBackedSecureStore;

/**
 * Credential Manager store for a token.
 */
public final class CredManagerBackedTokenStore extends CredManagerBackedSecureStore<Token> {

    static final String TOKEN_USERNAME = "PersonalAccessToken";

    @Override
    protected Token create(final String username, final String secret) {
        return new Token(secret, TokenType.Personal);
    }

    @Override
    protected String getUsername(final Token token) {
        return TOKEN_USERNAME;
    }

    @Override
    protected String getCredentialBlob(final Token token) {
        return token.getValue();
    }
}
