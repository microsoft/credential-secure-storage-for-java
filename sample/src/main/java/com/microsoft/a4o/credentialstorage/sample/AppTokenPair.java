// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.sample;

import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider;
import com.microsoft.a4o.credentialstorage.storage.StorageProvider.SecureOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class AppTokenPair {
    private static final String TOKEN_PAIR_KEY = "TestTokenPair";
    private static final BufferedReader INPUT = new BufferedReader(new InputStreamReader(System.in));

    private static final Logger log = LoggerFactory.getLogger(AppTokenPair.class);

    public static void main(String[] args) throws IOException {
        // Get a secure store instance
        final SecretStore<TokenPair> tokenPairStorage = StorageProvider.getTokenPairStorage(true, SecureOption.MUST);

        if (tokenPairStorage == null) {
            log.error("No secure token storage available.");
            return;
        }

        // Get token pair name from the user
        final String tokenPairName = getTokenPairName();

        // Retrieve the existing token pair from the store
        final TokenPair storedTokenPair = tokenPairStorage.get(tokenPairName);
        printTokenPair(tokenPairName, storedTokenPair);

        // Create a new token pair instance from user input
        log.info("Enter access token value: ");
        final String accessTokenValue = INPUT.readLine();
        log.info("Enter refresh token value: ");
        final String refreshTokenValue = INPUT.readLine();
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
        final String userInput = INPUT.readLine();
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

    private static String getTokenPairName() throws IOException {
        log.info("Enter token pair name [{}]: ", TOKEN_PAIR_KEY);
        String tokenPairName = INPUT.readLine();
        if (tokenPairName == null || tokenPairName.isEmpty()) tokenPairName = TOKEN_PAIR_KEY;
        return tokenPairName;
    }
}
