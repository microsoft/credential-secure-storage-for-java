// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.sample;

import com.microsoft.credentialstorage.secret.TokenPair;
import com.microsoft.credentialstorage.storage.SecretStore;
import com.microsoft.credentialstorage.storage.StorageProvider;
import com.microsoft.credentialstorage.storage.StorageProvider.SecureOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class AppTokenPair {
    private static final Logger log = LoggerFactory.getLogger(AppTokenPair.class);

    private static final String TOKEN_PAIR_KEY = "TestTokenPair";

    public static void main(String[] args) {
        // Get a secure store instance
        final SecretStore<TokenPair> tokenPairStorage = StorageProvider.getTokenPairStorage(true, SecureOption.MUST);

        // Get token pair name from the user
        final String tokenPairName = getTokenPairName();

        // Retrieve the existing token pair from the store
        final TokenPair storedTokenPair = tokenPairStorage.get(tokenPairName);
        printTokenPair(tokenPairName, storedTokenPair);

        // Create a new token pair instance from user input
        final char[] accessTokenValue = System.console().readPassword("Enter access token value: ");
        final char[] refreshTokenValue = System.console().readPassword("Enter refresh token value: ");
        TokenPair tokenPair = new TokenPair(accessTokenValue, refreshTokenValue);

        // Save the token pair to the store
        tokenPairStorage.add(tokenPairName, tokenPair);

        log.info("Added/Updated token pair under the key: {}", tokenPairName);

        // Retrieve new token pair from the store
        TokenPair newStoredTokenPair = tokenPairStorage.get(tokenPairName);

        log.info("Retrieved the updated token pair using the key: {}", tokenPairName);
        printTokenPair(tokenPairName, newStoredTokenPair);

        // Remove token pair from the store
        log.info("Remove the token pair under the key {} [Y/n]?", tokenPairName);
        final String userInput = System.console().readLine("Remove the token under the key %s [Y/n]?", tokenPair);
        if (!"n".equalsIgnoreCase(userInput)) {
            tokenPairStorage.delete(tokenPairName);
        }
    }

    private static void printTokenPair(final String tokenPairName, final TokenPair tokenPair) {
        if (tokenPair != null) {
            log.info("Retrieved the existing token pair using the key: " + tokenPairName);
            log.info("  Access token: {} (Type: {})", tokenPair.getAccessToken().getValue(), tokenPair.getAccessToken().getType());
            log.info("  Refresh token: {} (Type: {})", tokenPair.getRefreshToken().getValue(), tokenPair.getRefreshToken().getType());
        } else {
            log.info("No stored token pair under the key: {}", tokenPairName);
        }
    }

    private static String getTokenPairName() {
        String tokenPairName = System.console().readLine("Enter token pair name [%s]: ", TOKEN_PAIR_KEY);
        if (tokenPairName == null || tokenPairName.isEmpty()) tokenPairName = TOKEN_PAIR_KEY;
        return tokenPairName;
    }
}
