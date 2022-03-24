// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.windows;

import com.microsoft.credentialstorage.model.StoredSecret;
import com.microsoft.credentialstorage.SecretStore;
import com.sun.jna.LastErrorException;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;


/**
 * This class exposes functions to interact with Windows Credential Manager
 */
public abstract class CredManagerBackedSecureStore<E extends StoredSecret> implements SecretStore<E> {
    protected static final Logger logger = LoggerFactory.getLogger(CredManagerBackedSecureStore.class);
    private static final Charset UTF16LE = StandardCharsets.UTF_16LE;

    private final CredAdvapi32 INSTANCE = getCredAdvapi32Instance();

    /**
     * Read calls CredRead on Windows and retrieve the Secret
     *
     * Multi-thread safe, synchronized access to store
     *
     * @param key
     *      TargetName in the credential structure
     */
    @Override
    public E get(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Getting secret for {}", key);

        return readSecret(key, this::createSecret);
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
    public boolean delete(final String key) {
        Objects.requireNonNull(key, "key cannot be null");

        logger.info("Deleting secret for {}", key);

        return deleteSecret(key);
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
    public abstract boolean add(String key, E secret);

    /**
     * Windows credential manager is considered a secure storage for secrets
     *
     * @return {@code true} for Windows Credential Manager
     */
    @Override
    public boolean isSecure() {
        return true;
    }

    public static boolean isSupported() {
        return isWindows();
    }

    /**
     * Create a {@code Secret} from the native representation
     *
     * @param username
     *      username for the secret
     * @param secret
     *      password, oauth2 access token, or Personal Access Token
     *
     * @return a {@code Secret} from the input
     */
    protected abstract E create(String username, char[] secret);

    private E createSecret(final CredAdvapi32.CREDENTIAL credential) {
        final char[] secret = getSecret(credential);
        return create(credential.UserName, secret);
    }

    protected char[] getSecret(final CredAdvapi32.CREDENTIAL credential) {
        final byte[] secretData = credential.CredentialBlob.getByteArray(0, credential.CredentialBlobSize);
        return UTF16LEGetString(secretData);
    }

    protected <T> T readSecret(final String key, final Function<CredAdvapi32.CREDENTIAL, T> mapper) {
        T cred = null;

        final CredAdvapi32.PCREDENTIAL pcredential = new CredAdvapi32.PCREDENTIAL();
        boolean read;

        try {
            // MSDN doc doesn't mention threading safety, so let's just be careful and synchronize the access
            synchronized (INSTANCE) {
                read = INSTANCE.CredRead(key, CredAdvapi32.CRED_TYPE_GENERIC, 0, pcredential);
            }

            if (read) {
                final CredAdvapi32.CREDENTIAL credential = new CredAdvapi32.CREDENTIAL(pcredential.credential);
                cred = mapper.apply(credential);
            }

        } catch (final LastErrorException e) {
            logger.error("Getting secret failed. {}", e.getMessage());
        } finally {
            if (pcredential.credential != null) {
                synchronized (INSTANCE) {
                    INSTANCE.CredFree(pcredential.credential);
                }
            }
        }

        return cred;
    }

    protected boolean writeSecret(final String key, final String username, final char[] secret) {
        final byte[] credBlob = UTF16LEGetBytes(secret);

        final CredAdvapi32.CREDENTIAL cred = buildCred(key, username, credBlob);

        try {
            synchronized (INSTANCE) {
                INSTANCE.CredWrite(cred, 0);
            }

            return true;
        }
        catch (LastErrorException e) {
            logger.error("Adding secret failed. {}", e.getMessage());
            return false;
        } finally {
            cred.CredentialBlob.clear(credBlob.length);
            Arrays.fill(credBlob, (byte) 0);
        }
    }

    protected boolean deleteSecret(final String key) {
        try {
            synchronized (INSTANCE) {
                return INSTANCE.CredDelete(key, CredAdvapi32.CRED_TYPE_GENERIC, 0);
            }
        } catch (LastErrorException e) {
            logger.error("Deleting secret failed. {}", e.getMessage());
            return false;
        }
    }

    static CredAdvapi32.CREDENTIAL buildCred(final String key, final String username, final byte[] credentialBlob) {
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

    private static Pointer getPointer(final byte[] array) {
        Pointer p = new Memory(array.length);
        p.write(0, array, 0, array.length);

        return p;
    }

    private static byte[] UTF16LEGetBytes(final char[] value) {
        return UTF16LE.encode(CharBuffer.wrap(value)).array();
    }

    private static char[] UTF16LEGetString(final byte[] bytes) {
        return UTF16LE.decode(ByteBuffer.wrap(bytes)).array();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").startsWith("Windows");
    }

    private static CredAdvapi32 getCredAdvapi32Instance() {
        if (isSupported()) {
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
