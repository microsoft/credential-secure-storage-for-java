// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.storage.posix.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Simple interface to store and retrieve secrets with gnome-keyring
 *
 * https://developer.gnome.org/gnome-keyring/stable/ch01.html
 */
public interface GnomeKeyringLibrary extends Library {

    GnomeKeyringLibrary INSTANCE = Native.load("gnome-keyring", GnomeKeyringLibrary.class);

    /**
     * Save secrets to disk
     */
    String GNOME_KEYRING_DEFAULT = null;

    /**
     * Save secrets in memory
     */
    String GNOME_KEYRING_SESSION = "session";

    /**
     * GnomeKeyringResult:
     *  GNOME_KEYRING_RESULT_OK,
     *  GNOME_KEYRING_RESULT_DENIED,
     *  GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON,
     *  GNOME_KEYRING_RESULT_ALREADY_UNLOCKED,
     *  GNOME_KEYRING_RESULT_NO_SUCH_KEYRING,
     *  GNOME_KEYRING_RESULT_BAD_ARGUMENTS,
     *  GNOME_KEYRING_RESULT_IO_ERROR,
     *  GNOME_KEYRING_RESULT_CANCELLED,
     *  GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS,
     *  GNOME_KEYRING_RESULT_NO_MATCH
     */
    int GNOME_KEYRING_RESULT_OK                     = 0;
    int GNOME_KEYRING_RESULT_DENIED                 = 1;
    int GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON      = 2;
    int GNOME_KEYRING_RESULT_ALREADY_UNLOCKED       = 3;
    int GNOME_KEYRING_RESULT_NO_SUCH_KEYRING        = 4;
    int GNOME_KEYRING_RESULT_BAD_ARGUMENTS          = 5;
    int GNOME_KEYRING_RESULT_IO_ERROR               = 6;
    int GNOME_KEYRING_RESULT_CANCELLED              = 7;
    int GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS = 8;
    int GNOME_KEYRING_RESULT_NO_MATCH               = 9;

    /**
     * The item types
     *  GNOME_KEYRING_ITEM_GENERIC_SECRET = 0,
     *  GNOME_KEYRING_ITEM_NETWORK_PASSWORD,
     *  GNOME_KEYRING_ITEM_NOTE,
     *  GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD,
     *  GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD,
     *
     *  GNOME_KEYRING_ITEM_PK_STORAGE = 0x100,
     *
     * Not used, remains here only for compatibility
     *  GNOME_KEYRING_ITEM_LAST_TYPE,
     */
    int GNOME_KEYRING_ITEM_GENERIC_SECRET           = 0;
    int GNOME_KEYRING_ITEM_NETWORK_PASSWORD         = 1;
    int GNOME_KEYRING_ITEM_NOTE                     = 2;
    int GNOME_KEYRING_ITEM_CHAINED_KEYRING_PASSWORD = 3;
    int GNOME_KEYRING_ITEM_ENCRYPTION_KEY_PASSWORD  = 4;

    /**
     * GnomeKeyringAttributeType:
     *   GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
     *   GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32
     */
    int GNOME_KEYRING_ATTRIBUTE_TYPE_STRING         = 0;
    int GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32         = 1;


    /**
     * Item Attributes — Attributes of individual keyring items.
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Item-Attributes.html
     */
    class GnomeKeyringPasswordSchemaAttribute extends Structure {

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("name", "type");
        }

        public String name;

        public int type;
    }

    /**
     * Schema for secret
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html#GnomeKeyringPasswordSchema
     */
    class GnomeKeyringPasswordSchema extends Structure {

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("item_type", "attributes");
        }

        public int item_type;

        public GnomeKeyringPasswordSchemaAttribute[] attributes = new GnomeKeyringPasswordSchemaAttribute[32];
    }

    /**
     * A pointer to pointer helper structure
     */
    class PointerToPointer extends Structure {

        @Override
        protected List<String> getFieldOrder() {
            return Collections.singletonList("pointer");
        }

        public Pointer pointer;
    }

    /**
     * Storing a secret, without paraphrasing, please read:
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html#gnome-keyring-store-password-sync
     *
     * @param schema
     *      schema for the secret
     * @param keyring
     *      "session" means in memory; {@code null} for default on disk storage
     * @param display_name
     *      display name of this secret
     * @param password
     *      actual password
     * @param args
     *      varargs, attributes of the secret, please read the API document
     *
     * @return
     *      return code
     */
    int gnome_keyring_store_password_sync(final GnomeKeyringPasswordSchema schema,
                                          final String keyring,
                                          final String display_name,
                                          final String password,
                                          Object... args);

    /**
     * Retrieving a stored secret, without paraphrasing, please read:
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html#gnome-keyring-find-password-sync
     *
     * @param schema
     *      schema for the secret
     * @param pPassword
     *      pointer to pointer of the retrieved secret
     * @param args
     *      varargs used to locate the secret
     *
     * @return
     *      return code
     */
    int gnome_keyring_find_password_sync(final GnomeKeyringPasswordSchema schema,
                                         final PointerToPointer pPassword,
                                         Object... args);

    /**
     * Delete a stored secret, without paraphrasing, please read:
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html#gnome-keyring-delete-password-sync
     *
     * @param schema
     *      schema for the secret
     * @param args
     *      varargs used to locate the secret
     *
     * @return
     *      return code
     */
    int gnome_keyring_delete_password_sync(final GnomeKeyringPasswordSchema schema,
                                           Object... args);


    /**
     * Free the in memory secret pointer, without paraphrasing, please read:
     *
     * https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Simple-Password-Storage.html#gnome-keyring-free-password
     *
     * @param password
     *      pointer to the secret to be freed
     */
    void gnome_keyring_free_password(final Pointer password);

    /**
     * Get information about keyring.
     * The GnomeKeyringInfo structure returned in info must be freed with gnome_keyring_info_free().
     *
     * @param keyring
     *    keyring name
     * @param keyring_info
     *    pointer to pointer to keyring info
     *
     * @return
     *    return code
     */
    int gnome_keyring_get_info_sync(final String keyring, PointerToPointer keyring_info);

    /**
     * Free the keyring info pointer return by gnome_keyring_get_info_sync
     *
     * If null pointer is passed nothing occurs.
     *
     * @param keyring_info
     *      pointer to keyring_info
     */
    void gnome_keyring_info_free(final Pointer keyring_info);

    /**
     * Get whether the keyring is locked or not.
     *
     * @param keyring_info
     *      pointer to keyring_info
     * @return
     *      {@code true} when the keyring is locked; {@code false} otherwise.
     */
    boolean gnome_keyring_info_get_is_locked(final Pointer keyring_info);

    /**
     * Unlock a keyring, so that its contents may be accessed.  If password is null, user
     * will be prompted for password to unlock the keyring.
     *
     * @param keyring
     *      keyring name
     * @param password
     *      password to unlock.  If password is null, user will be prompted.  
     *
     * @return
     *      {@code true} when the keyring is unlocked; {@code false} otherwise.
     */
    int gnome_keyring_unlock_sync(final String keyring, final String password);

    /**
     * Translate error code to human readable string
     *
     * @param errorCode
     *      keyring error code
     *
     * @return
     *      Error description
     */
    String gnome_keyring_result_to_message(final int errorCode);
}
