// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.credentialstorage.implementation.posix.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * Only expose one method to set application name to suppress
 * warning: "g_set_application_name not set"
 */
public interface GLibLibrary extends Library {
    GLibLibrary INSTANCE = Native.load("glib-2.0", GLibLibrary.class);

    class GArray extends Structure {
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("data", "len");
        }

        public Pointer data;
        public int len;

        public GArray() {}

        public GArray(Pointer p) {
            super(p);
            read();
        }
    }

    class GList extends Structure {
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("data", "next", "prev");
        }

        public Pointer data;
        public Pointer next;
        public Pointer prev;

        public GList() {}

        public GList(Pointer p) {
            super(p);
            read();
        }
    }

    void g_set_application_name(String application_name);

    Pointer g_array_new(int zero_terminated, int clear, int element_size);

    void g_error_free(Pointer error);

    Pointer g_list_append(Pointer list, Pointer element);

    Pointer g_hash_table_new(Pointer hash_func, Pointer key_equal_func);
    boolean g_hash_table_insert(Pointer hash_table, Pointer key, Pointer value);
    Pointer g_hash_table_lookup(Pointer hash_table, Pointer key);
    void g_hash_table_destroy(Pointer hash_table);
    void g_hash_table_unref(Pointer hash_table);
}
