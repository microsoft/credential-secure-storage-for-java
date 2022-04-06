// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix.keyring;

import com.microsoft.a4o.credentialstorage.helpers.SystemHelper;
import com.microsoft.a4o.credentialstorage.secret.Secret;
import com.microsoft.a4o.credentialstorage.storage.SecretStore;
import com.microsoft.a4o.credentialstorage.storage.posix.internal.GLibInitializer;
import com.microsoft.a4o.credentialstorage.storage.posix.internal.GnomeKeyringLibrary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Base class for GNOME Keyring stores.
 * @param <E> secret class to store
 */
public abstract class GnomeKeyringBackedSecureStore<E extends Secret> implements SecretStore<E> {
    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedSecureStore.class);

    protected static final GnomeKeyringLibrary INSTANCE = getGnomeKeyringLibrary();
    protected static final GnomeKeyringLibrary.GnomeKeyringPasswordSchema SCHEMA = getGnomeKeyringPasswordSchema();

    protected static final String ALLOW_UNLOCK_KEYRING = "AUTH_LIB_ALLOW_UNLOCK_GNOME_KEYRING";


    /**
     * Return the type of this secure store, used to match the secret in GNOME Keyring
     *
     * @return type string representation of the secret type
     */
    protected abstract String getType();

    @Override
    public boolean delete(final String key) {
        Objects.requireNonNull(key, "key cannot be null");
        logger.info("Deleting {} for {}", getType(), key);

        final int result = INSTANCE.gnome_keyring_delete_password_sync(
                SCHEMA,
                "Type", getType(),
                "Key", key,
                null);

        return checkResult(result, "Could not delete secret from storage");
    }

    /**
     * GNOME Keyring is considered secure
     *
     * @return {@code true} for GNOME Keyring
     */
    @Override
    public boolean isSecure() {
        return true;
    }

    protected char[] getSecret(final String key) {
        final GnomeKeyringLibrary.PointerToPointer pPassword = new GnomeKeyringLibrary.PointerToPointer();
        char[] secret = null;
        try {
            final int result = INSTANCE.gnome_keyring_find_password_sync(
                    SCHEMA,
                    pPassword,
                    "Type", getType(),
                    "Key", key,
                    null);
            if (checkResult(result, "Could not retrieve secret from storage.")) {
                secret = pPassword.pointer.getString(0).toCharArray();
            }
        } finally {
            if (pPassword.pointer != null) {
                INSTANCE.gnome_keyring_free_password(pPassword.pointer);
            }
        }

        return secret;
    }

    /**
     * Check for GNOME Keyring support on this platform
     *
     * @return {@code true} if gnome-keyring library is available; {@code false} otherwise
     */
    public static boolean isGnomeKeyringSupported() {
        try {
            if (INSTANCE != null && SCHEMA != null) {
                // If we are here that means we have loaded gnome-keyring library
                final GnomeKeyringLibrary.PointerToPointer keyring_info = getGnomeKeyringInfoStruct();
                if (keyring_info != null) {
                    try {
                        return isSimplePasswordAPISupported() && isGnomeKeyringUnlocked(keyring_info);
                    } finally {
                        INSTANCE.gnome_keyring_info_free(keyring_info.pointer);
                    }
                }
            }
        } catch (final Throwable t) {
            logger.warn("Gnome Keyring is not available.", t);
        }

        return false;
    }

    private static GnomeKeyringLibrary.PointerToPointer getGnomeKeyringInfoStruct() { 
        // First make sure we can access gnome-keyring (ssh session may have trouble accessing gnome-keyring)     
        final GnomeKeyringLibrary.PointerToPointer keyring_info_container = new GnomeKeyringLibrary.PointerToPointer();
        final int ret  = INSTANCE.gnome_keyring_get_info_sync(
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, keyring_info_container);

        return checkResult(ret, "Could not get default keyring info. GNOME Keyring is not available.")
                ? keyring_info_container : null;
    }

    private static boolean isSimplePasswordAPISupported() {
        // Simple password API is introduced in v2.22.  Unfortunately there is no easy way to discover the version
        // of Gnome Keyring library

        // Make sure gnome-keyring supports simple password API - this check does not require 
        // keyring to be unlocked first 
        logger.debug("Try access gnome-keyring with dummy data to make sure it's accessible...");
        try {
            GnomeKeyringLibrary.PointerToPointer pPassword = new GnomeKeyringLibrary.PointerToPointer();
            INSTANCE.gnome_keyring_find_password_sync(
                    SCHEMA,
                    pPassword,
                    // The following two values should not match anything, calling this method purely
                    // to determine existence of this function since we have no version information
                    "Type", "NullType",
                    "Key", "NullKey",
                    null
                    );
        } catch (UnsatisfiedLinkError error) {
            logger.warn("GNOME Keyring on this platform does not support the simple password API.  " +
                    "We require gnome-keyring 2.22+.");

            return false;
        }

        return true;
    }

    private static boolean isGnomeKeyringUnlocked(final GnomeKeyringLibrary.PointerToPointer keyring_info) {
        // Make sure it's not locked, and unlock it if user allows it (usually by popping up a dialog
        // asking for user's password
        final boolean locked = INSTANCE.gnome_keyring_info_get_is_locked(keyring_info.pointer);

        if (locked) {
            logger.info("Keyring is locked, most likely due to UI is unavailable or user logged in " +
                    "automatically without supplying a password.");

            final boolean allowUnlock = Boolean.parseBoolean(System.getProperty(ALLOW_UNLOCK_KEYRING));
            if (allowUnlock) {
                final int ret = INSTANCE.gnome_keyring_unlock_sync(GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, null);
                return checkResult(ret, "Could not unlock keyring. GNOME Keyring is not available.");
            } else {
                logger.info("Keyring is locked and unavailable, please set variable {} to " +
                        "allow unlocking the keyring with a popup dialog.", ALLOW_UNLOCK_KEYRING); 

                return false;
            }
        }

        return true;
    }

    private static boolean isGnomeKeyringLibraryAvailable() {
        if (SystemHelper.isLinux()) {
            try {
                // First make sure gnome-keyring library exists
                GnomeKeyringLibrary ignored = GnomeKeyringLibrary.INSTANCE;

                // Try set the application name to avoid warnings while we initialize -- if this fails,
                // it's okay, it is not end of the world but user will see some warnings printed on screen
                try {
                    GLibInitializer.getInstance().initialize();
                } catch (final UnsatisfiedLinkError error) {
                    logger.warn("Glib not available -- user will see warnings printed on screen. Those warnings are " +
                            "not serious and can be ignored.");
                }

                return true;
            } catch (final Throwable t) {
                // ignore error
                logger.info("gnome-keyring library not loaded", t);
            }
        }

        return false;
    }

    private static GnomeKeyringLibrary getGnomeKeyringLibrary() {
        return isGnomeKeyringLibraryAvailable() ? GnomeKeyringLibrary.INSTANCE : null;
    }

    private static GnomeKeyringLibrary.GnomeKeyringPasswordSchema getGnomeKeyringPasswordSchema() {
        try {
            if (isGnomeKeyringLibraryAvailable()) {
                logger.info("gnome-keyring library loaded, creating a password SCHEMA");
                GnomeKeyringLibrary.GnomeKeyringPasswordSchema schema
                        = new GnomeKeyringLibrary.GnomeKeyringPasswordSchema();

                schema.item_type = GnomeKeyringLibrary.GNOME_KEYRING_ITEM_GENERIC_SECRET;
                //Type and Key, all fields are strings
                schema.attributes = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute[3];
                schema.attributes[0] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[0].name = "Type";
                schema.attributes[0].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

                schema.attributes[1] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[1].name = "Key";
                schema.attributes[1].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

                // Terminating
                schema.attributes[2] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
                schema.attributes[2].name = null;
                schema.attributes[2].type = 0;

                return schema;

            } else {
                logger.info("gnome-keyring library not loaded, return null for SCHEMA");
            }
        } catch (final Throwable t) {
            logger.warn("creating SCHEMA failed, return null for SCHEMA.", t);
        }

        return null;
    }

    protected static boolean checkResult(final int retCode, final String message) {
        if (retCode != GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK) {
            logger.error(message);
            try {
                logger.error("Return code: {} description: {}", retCode, INSTANCE.gnome_keyring_result_to_message(retCode));
            } catch (UnsatisfiedLinkError e) {
                logger.error("Return code: {}", retCode);
            }

            return false;
        }

        return true;
    }
}
