// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.windows.internal;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;
import com.microsoft.a4o.credentialstorage.helpers.SystemHelper;
import com.microsoft.a4o.credentialstorage.secret.Secret;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.sun.jna.LastErrorException;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Objects;

/**
 * This class exposes functions to interact with Windows Credential Manager
 */
public abstract class CredManagerBackedSecureStore<E extends Secret> implements SecretStore<E> {

    private static final Logger logger = LoggerFactory.getLogger(CredManagerBackedSecureStore.class);

    private final CredAdvapi32 INSTANCE = getCredAdvapi32Instance();

    /**
     * Create a {@code Secret} from the string representation
     *
     * @param username
     *      username for the secret
     * @param secret
     *      password, oauth2 access token, or Personal Access Token
     *
     * @return a {@code Secret} from the input
     */
    protected abstract E create(String username, String secret);

    /**
     * Get String representation of the UserName field from the {@code Secret}
     *
     * @param secret
     *      A {@code Credential}, {@code Token} or {@code TokenPair}
     *
     * @return username from this secret
     */
    protected abstract String getUsername(E secret);

    /**
     * Get String representation of the CredentialBlob field from the secret
     *
     * @param secret
     *      A {@code Credential}, {@code Token} or {@code TokenPair}
     *
     * @return credential from this secre
     */
    protected abstract String getCredentialBlob(E secret);

    /**
     * Read calls CredRead on Windows and retrieve the Secret
     *
     * Multi-thread safe, synchronized access to store
     *
     * @param key
     *      TargetName in the credential structure
     */
    @Override
    public E get(String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting secret for {}", key);

        final CredAdvapi32.PCREDENTIAL pcredential = new CredAdvapi32.PCREDENTIAL();
        boolean read;
        E cred;

        try {
            // MSDN doc doesn't mention threading safety, so let's just be careful and synchronize the access
            synchronized (INSTANCE) {
                read = INSTANCE.CredRead(key, CredAdvapi32.CRED_TYPE_GENERIC, 0, pcredential);
            }

            if (read) {
                final CredAdvapi32.CREDENTIAL credential = new CredAdvapi32.CREDENTIAL(pcredential.credential);

                byte[] secretBytes = credential.CredentialBlob.getByteArray(0, credential.CredentialBlobSize);
                final String secret = StringHelper.UTF16LEGetString(secretBytes);
                final String username = credential.UserName;

                cred = create(username, secret);

            } else {
                cred = null;
            }

        } catch (final LastErrorException e) {
            logger.error("Getting secret failed.", e);
            cred = null;

        } finally {
            if (pcredential.credential != null) {
                synchronized (INSTANCE) {
                    INSTANCE.CredFree(pcredential.credential);
                }
            }
        }

        return cred;
    }

    /**
     * Delete the stored credential from Credential Manager
     *
     * Multi-thread safe, synchronized access to store
     *
     * @param key
     *      TargetName in the credential structure
     *
     * @return
     *      true if delete successful, false otherwise (including key doesn't exist)
     */
    @Override
    public boolean delete(String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Deleting secret for {}", key);

        try {
            synchronized (INSTANCE) {
                return INSTANCE.CredDelete(key, CredAdvapi32.CRED_TYPE_GENERIC, 0);
            }
        } catch (LastErrorException e) {
            logger.error("Deleting secret failed.", e);
            return false;
        }
    }

    /**
     * Add the specified secret to Windows Credential Manager
     *
     * Multi-thread safe, synchronized access to store
     * @param key
     *      TargetName in the credential structure
     * @param secret
     *      secret to be stored
     *
     * @return {@code true} if successfully added
     *         {@code false} otherwise
     */
    @Override
    public boolean add(String key, E secret) {
        Objects.requireNonNull(key, "key cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");

        logger.info("Adding secret for {}", key);

        final String username = getUsername(secret);
        final String credentialBlob = getCredentialBlob(secret);
        byte[] credBlob = StringHelper.UTF16LEGetBytes(credentialBlob);

        final CredAdvapi32.CREDENTIAL cred = buildCred(key, username, credBlob);

        try {
            synchronized (INSTANCE) {
                INSTANCE.CredWrite(cred, 0);
            }

            return true;
        }
        catch (LastErrorException e) {
            logger.error("Adding secret failed.", e);
            return false;
        } finally {
            cred.CredentialBlob.clear(credBlob.length);
            Arrays.fill(credBlob, (byte) 0);
        }
    }

    /**
     * Windows credential manager is considered a secure storage for secrets
     *
     * @return {@code true} for Windows Credential Manager
     */
    @Override
    public boolean isSecure() {
        return true;
    }

    private CredAdvapi32.CREDENTIAL buildCred(String key, String username, byte[] credentialBlob) {
        final CredAdvapi32.CREDENTIAL credential = new CredAdvapi32.CREDENTIAL();

        credential.Flags = 0;
        credential.Type = CredAdvapi32.CRED_TYPE_GENERIC;
        credential.TargetName = key;


        credential.CredentialBlobSize = credentialBlob.length;
        credential.CredentialBlob = getPointer(credentialBlob);

        credential.Persist = CredAdvapi32.CRED_PERSIST_LOCAL_MACHINE;
        credential.UserName = username;

        return credential;
    }

    private Pointer getPointer(byte[] array) {
        Pointer p = new Memory(array.length);
        p.write(0, array, 0, array.length);

        return p;
    }

    private static CredAdvapi32 getCredAdvapi32Instance() {
        if (SystemHelper.isWindows()) {
            return CredAdvapi32.INSTANCE;
        } else {
            logger.warn("Returning a dummy library on non Windows platform.  " +
                    "This is a bug unless you are testing.");

            // Return a dummy on other platforms
            return new CredAdvapi32() {
                @Override
                public boolean CredRead(String targetName, int type, int flags, PCREDENTIAL pcredential) throws LastErrorException {
                    return false;
                }

                @Override
                public boolean CredWrite(CREDENTIAL credential, int flags) throws LastErrorException {
                    return false;
                }

                @Override
                public boolean CredDelete(String targetName, int type, int flags) throws LastErrorException {
                    return false;
                }

                @Override
                public void CredFree(Pointer credential) throws LastErrorException {

                }
            };
        }
    }
}
