// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

module credential.secure.storage {
    requires java.xml;
    requires com.sun.jna;
    requires org.slf4j;
    requires com.sun.jna.platform;

    exports com.microsoft.credentialstorage.secret;
    exports com.microsoft.credentialstorage.storage;
}