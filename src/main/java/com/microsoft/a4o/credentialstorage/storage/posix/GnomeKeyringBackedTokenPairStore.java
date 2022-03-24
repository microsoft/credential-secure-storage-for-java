// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.a4o.credentialstorage.storage.posix;

import com.microsoft.a4o.credentialstorage.helpers.StringHelper;
import com.microsoft.a4o.credentialstorage.secret.TokenPair;
import com.microsoft.a4o.credentialstorage.storage.posix.internal.GnomeKeyringBackedSecureStore;
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

public class GnomeKeyringBackedTokenPairStore extends GnomeKeyringBackedSecureStore<TokenPair> {

    private static final Logger logger = LoggerFactory.getLogger(GnomeKeyringBackedTokenPairStore.class);

    @Override
    protected String serialize(final TokenPair tokenPair) {
        Objects.requireNonNull(tokenPair, "TokenPair cannot be null");

        return toXmlString(tokenPair);
    }

    @Override
    protected TokenPair deserialize(final String secret) {
        Objects.requireNonNull(secret, "secret cannot be null");

        try {
            return fromXmlString(secret);
        } catch (final Exception e) {
            logger.error("Failed to deserialize the stored secret. Return null.", e);
            return null;
        }
    }

    @Override
    protected String getType() {
        return "OAuth2Token";
    }

    static TokenPair fromXml(final Node tokenPairNode) {
        TokenPair value;

        String accessToken = null;
        String refreshToken = null;

        final NodeList propertyNodes = tokenPairNode.getChildNodes();
        for (int v = 0; v < propertyNodes.getLength(); v++) {
            final Node propertyNode = propertyNodes.item(v);
            final String propertyName = propertyNode.getNodeName();
            if ("accessToken".equals(propertyName)) {
                accessToken = XmlHelper.getText(propertyNode);
            } else if ("refreshToken".equals(propertyName)) {
                refreshToken = XmlHelper.getText(propertyNode);
            }
        }

        value = new TokenPair(accessToken, refreshToken);
        return value;
    }

    static Element toXml(final TokenPair tokenPair, final Document document) {
        final Element valueNode = document.createElement("value");

        final Element accessTokenNode = document.createElement("accessToken");
        final Text accessTokenValue = document.createTextNode(tokenPair.getAccessToken().getValue());
        accessTokenNode.appendChild(accessTokenValue);
        valueNode.appendChild(accessTokenNode);

        final Element refreshTokenNode = document.createElement("refreshToken");
        final Text refreshTokenValue = document.createTextNode(tokenPair.getRefreshToken().getValue());
        refreshTokenNode.appendChild(refreshTokenValue);
        valueNode.appendChild(refreshTokenNode);

        return valueNode;
    }

    private static String toXmlString(final TokenPair tokenPair) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.newDocument();

            final Element element = toXml(tokenPair, document);
            document.appendChild(element);

            return XmlHelper.toString(document);
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    private static TokenPair fromXmlString(final String xmlString) {
        final byte[] bytes = StringHelper.UTF8GetBytes(xmlString);
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        return fromXmlStream(inputStream);
    }

    private static TokenPair fromXmlStream(final InputStream source) {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
            final Document document = builder.parse(source);
            final Element rootElement = document.getDocumentElement();

            return fromXml(rootElement);
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }
}
