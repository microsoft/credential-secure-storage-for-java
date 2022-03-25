// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix.keyring;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;
import com.microsoft.a4o.credentialstorage.secret.Credential;
import com.microsoft.a4o.credentialstorage.storage.posix.XmlHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Objects;

/**
 * GNOME Keyring store for a credential.
 */
public final class GnomeKeyringBackedCredentialStore extends GnomeKeyringBackedSecureStore<Credential> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedCredentialStore.class);

    @Override
    protected String getType() {
        return "Credential";
    }

    @Override
    protected String serialize(final Credential credential) {
        Objects.requireNonNull(credential, "Credential cannot be null");

        return toXmlString(credential);
    }

    @Override
    protected Credential deserialize(final String secret) {
        Objects.requireNonNull(secret, "secret cannot be null");

        try {
            return fromXmlString(secret);
        } catch (final Exception e) {
            logger.error("Failed to deserialize credential.", e);
            return null;
        }
    }

    private static Credential fromXmlString(final String xmlString) {
        final byte[] bytes = StringHelper.UTF8GetBytes(xmlString);
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        return fromXmlStream(inputStream);
    }

    private static Credential fromXmlStream(final InputStream source) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.parse(source);
            final Element rootElement = document.getDocumentElement();

            return fromXml(rootElement);
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    private static String toXmlString(final Credential credential) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.newDocument();

            final Element element = toXml(credential, document);
            document.appendChild(element);

            return XmlHelper.toString(document);
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    static Credential fromXml(final Node credentialNode) {
        Credential value;
        String password = null;
        String username = null;

        final NodeList propertyNodes = credentialNode.getChildNodes();
        for (int v = 0; v < propertyNodes.getLength(); v++) {
            final Node propertyNode = propertyNodes.item(v);
            if (propertyNode.getNodeType() != Node.ELEMENT_NODE) continue;

            final String propertyName = propertyNode.getNodeName();
            if ("Password".equals(propertyName)) {
                password = XmlHelper.toString(propertyNode);
            } else if ("Username".equals(propertyName)) {
                username = XmlHelper.toString(propertyNode);
            }
        }
        value = new Credential(username, password);
        return value;
    }

    static Element toXml(final Credential credential, final Document document) {
        final Element valueNode = document.createElement("value");

        final Element passwordNode = document.createElement("Password");
        final Text passwordValue = document.createTextNode(credential.getPassword());
        passwordNode.appendChild(passwordValue);
        valueNode.appendChild(passwordNode);

        final Element usernameNode = document.createElement("Username");
        final Text usernameValue = document.createTextNode(credential.getUsername());
        usernameNode.appendChild(usernameValue);
        valueNode.appendChild(usernameNode);

        return valueNode;
    }
}
