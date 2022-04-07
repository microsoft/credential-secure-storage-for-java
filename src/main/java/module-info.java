// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

module credential.secure.storage {
    requires com.sun.jna;
    requires com.sun.jna.platform;
    requires org.slf4j;

    exports com.microsoft.credentialstorage.model;
    exports com.microsoft.credentialstorage;
}