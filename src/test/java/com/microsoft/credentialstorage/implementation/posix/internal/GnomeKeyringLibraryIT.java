// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.internal;

import com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringBackedSecureStore;
import com.microsoft.credentialstorage.implementation.posix.keyring.GnomeKeyringLibrary;
import org.junit.Before;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

public class GnomeKeyringLibraryIT {

    GnomeKeyringLibrary underTest;
    GnomeKeyringLibrary.GnomeKeyringPasswordSchema schema;

    @Before
    public void setUp() {
        //Only test on platform that has gnome-keyring support
        assumeTrue(GnomeKeyringBackedSecureStore.isSupported());

        underTest = GnomeKeyringLibrary.INSTANCE;
        schema = new GnomeKeyringLibrary.GnomeKeyringPasswordSchema();
        schema.item_type = GnomeKeyringLibrary.GNOME_KEYRING_ITEM_GENERIC_SECRET;
        schema.attributes = getAttributes();
    }

    @Test
    public void e2e() {
        final String type = "PersonalAccessToken";

        final String password1 = "testingPassword";
        final String password2 = "testingPassword2";
        final String password3 = create8192CharLongPassword();
        final String key1 = "http://testingurl.com";
        final String key2 = "http://another.testingurl.com";
        final String key3 = "http://another.testingurl.org";

        // Write a credential to gnome-keyring
        int result = underTest.gnome_keyring_store_password_sync(
                schema,
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, //save to disk
                "E2E Manual Testing Secret", // display name
                password1,
                //attributes list
                "Type", type,
                "Key", key1,
                null
                );

        assertEquals("Could not store password1 with result: " + result,
                GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);

        result = underTest.gnome_keyring_store_password_sync(
                schema,
                GnomeKeyringLibrary.GNOME_KEYRING_SESSION, //save to memory only
                "E2E Manual Testing Secret", // same display name
                password2,
                //attributes list
                "Type", type,
                "Key", key2,
                null
        );

        assertEquals("Could not store password2 with result: " + result,
                GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);

        result = underTest.gnome_keyring_store_password_sync(
                schema,
                GnomeKeyringLibrary.GNOME_KEYRING_DEFAULT, //save to disk
                "E2E Manual Testing Secret", // same display name
                password3,
                //attributes list
                "Type", type,
                "Key", key3,
                null
        );

        assertEquals("Could not store password3 with result: " + result,
                GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);

        // It is a good thing to break after here and verify from any GUI keyring program you have to
        // confirm password2 is only saved in memory, it shouldn't appear in the default keyring; and
        // in the default keyring there are two items with identical description string

        // read out first password
        GnomeKeyringLibrary.PointerToPointer p = new GnomeKeyringLibrary.PointerToPointer();
        result = underTest.gnome_keyring_find_password_sync(
                schema,
                p,
                "Type", type,
                "Key", key1,
                null);

        assertEquals("Could not read password1 with result: " + result,
                GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);

        assertEquals("Password1 incorrectly read", password1, p.pointer.getString(0));

        // read out 3rd password
        GnomeKeyringLibrary.PointerToPointer p3 = new GnomeKeyringLibrary.PointerToPointer();
        result = underTest.gnome_keyring_find_password_sync(
                schema,
                p3,
                "Type", type,
                "Key", key3,
                null);

        assertEquals("Could not read password3 with result: " + result,
                GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);

        assertEquals("Password3 incorrectly read", password3, p3.pointer.getString(0));

        // let's clear out the pointers
        underTest.gnome_keyring_free_password(p.pointer);
        underTest.gnome_keyring_free_password(p3.pointer);

        // now let's delete them all
        result = underTest.gnome_keyring_delete_password_sync(schema, "Type", type, "Key", key1, null);
        assertEquals(GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);
        result = underTest.gnome_keyring_delete_password_sync(schema, "Type", type, "Key", key2, null);
        assertEquals(GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);
        result = underTest.gnome_keyring_delete_password_sync(schema, "Type", type, "Key", key3, null);
        assertEquals(GnomeKeyringLibrary.GNOME_KEYRING_RESULT_OK, result);

        // now read password1 should fail

        GnomeKeyringLibrary.PointerToPointer pAgain = new GnomeKeyringLibrary.PointerToPointer();
        result = underTest.gnome_keyring_find_password_sync(
                schema,
                pAgain,
                "Type", type,
                "Key", key1,
                null);

        assertEquals("Read password1 didn't result in no match? " + result,
                GnomeKeyringLibrary.GNOME_KEYRING_RESULT_NO_MATCH, result);
    }

    private String create8192CharLongPassword() {
        Random rand = new Random();
        char[] password = new char[8192];
        for(int i = 0; i < 8192; ++i) {
            password[i] = (char)(rand.nextInt(26) + 'a');
        }

        return new String(password);
    }

    private GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute[] getAttributes() {
        //create a testing schema's attributes
        final GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute[] attributes
                            = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute[3];

        // type = token type; key = url entry with prefixes
        attributes[0] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
        attributes[0].name = "Type";
        attributes[0].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
        attributes[1] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
        attributes[1].name = "Key";
        attributes[1].type = GnomeKeyringLibrary.GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;

        // terminating attribute
        attributes[2] = new GnomeKeyringLibrary.GnomeKeyringPasswordSchemaAttribute();
        attributes[2].name = null;
        attributes[2].type = 0;

        return attributes;
    }
}
