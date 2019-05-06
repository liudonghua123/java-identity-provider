/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.saml.attribute.transcoding.impl;

import java.util.Properties;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.LocalizedStringAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAML1AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.SAMLEncoderSupport;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml1.core.AttributeDesignator;
import org.opensaml.saml.saml1.core.AttributeValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link net.shibboleth.idp.attribute.AttributeTranscoder} that supports {@link AttributeDesignator} and
 * {@link StringAttributeValue} objects.
 */
public class SAML1StringAttributeTranscoder extends AbstractSAML1AttributeTranscoder<StringAttributeValue> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(SAML1StringAttributeTranscoder.class);

    /** {@inheritDoc} */
    @Override protected boolean canEncodeValue(@Nonnull final IdPAttribute attribute,
            @Nonnull final IdPAttributeValue value) {
        return value instanceof StringAttributeValue;
    }

    /** {@inheritDoc} */
    @Override @Nullable protected XMLObject encodeValue(@Nullable final ProfileRequestContext profileRequestContext,
            @Nonnull final IdPAttribute attribute, @Nonnull final Properties properties,
            @Nonnull final StringAttributeValue value) throws AttributeEncodingException {
        
        if (value instanceof LocalizedStringAttributeValue || value instanceof ScopedStringAttributeValue) {
            log.warn("Attribute '{}': Lossy encoding of attribute value of type {} to SAML1 String Attribute",
                    attribute.getId(), value.getClass().getSimpleName());
        }
        
        final Object encodeType = properties.getOrDefault(PROP_ENCODE_TYPE, Boolean.TRUE);
        
        return SAMLEncoderSupport.encodeStringValue(attribute,
                AttributeValue.DEFAULT_ELEMENT_NAME, value.getValue(),
                encodeType instanceof Boolean ? (Boolean) encodeType : true);
    }

    /** {@inheritDoc} */
    @Override @Nullable protected IdPAttributeValue<?> decodeValue(
            @Nullable final ProfileRequestContext profileRequestContext, @Nonnull final AttributeDesignator attribute,
            @Nonnull final Properties properties, @Nullable final XMLObject value) {
        
        return value != null ? StringAttributeValue.valueOf(getStringValue(value)) : null;
    }
    
}