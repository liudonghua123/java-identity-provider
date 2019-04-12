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

package net.shibboleth.idp.saml.attribute.transcoding;

import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.AttributeDecodingException;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.IdPRequestedAttribute;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.saml.xml.SAMLConstants;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml1.core.Attribute;
import org.opensaml.saml.saml1.core.AttributeDesignator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

/**
 * Base class for transcoders that operate on a SAML 1 {@link Attribute} or {@link AttributeDesignator}.
 * 
 * @param <EncodedType> the type of data that can be handled by the transcoder
 */
public abstract class AbstractSAML1AttributeTranscoder<EncodedType extends IdPAttributeValue> extends
        AbstractSAMLAttributeTranscoder<AttributeDesignator,EncodedType> {

    /** The namespace of the attribute name. */
    @Nonnull @NotEmpty public static final String PROP_NAMESPACE = "namespace";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractSAML1AttributeTranscoder.class);
    
    /** Builder used to construct {@link Attribute} objects. */
    @Nonnull private final SAMLObjectBuilder<Attribute> attributeBuilder;

    /** Builder used to construct {@link AttributeDesignator} objects. */
    @Nonnull private final SAMLObjectBuilder<AttributeDesignator> designatorBuilder;
    
    /** Constructor. */
    public AbstractSAML1AttributeTranscoder() {
        attributeBuilder = (SAMLObjectBuilder<Attribute>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Attribute>getBuilderOrThrow(
                        Attribute.TYPE_NAME);
        designatorBuilder = (SAMLObjectBuilder<AttributeDesignator>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<AttributeDesignator>getBuilderOrThrow(
                        AttributeDesignator.TYPE_NAME);
    }

    /** {@inheritDoc} */
    @Nonnull public Class<AttributeDesignator> getEncodedType() {
        return AttributeDesignator.class;
    }
    
    /** {@inheritDoc} */
    @Nullable public String getEncodedName(@Nonnull final Properties properties) {
        
        try {
            // SAML 1 naming should be based on only what needs to be available from the properties alone.
            return new NamingFunction().apply(buildAttribute(null, null, AttributeDesignator.class, properties,
                    Collections.emptyList()));
        } catch (final AttributeEncodingException e) {
            return null;
        }
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected AttributeDesignator buildAttribute(@Nullable final ProfileRequestContext profileRequestContext,
            @Nullable final IdPAttribute attribute, @Nonnull final Class<? extends AttributeDesignator> to,
            @Nonnull final Properties properties, @Nonnull @NonnullElements final List<XMLObject> attributeValues)
                    throws AttributeEncodingException {

        if (attribute != null && !attribute.getValues().isEmpty() && attributeValues.isEmpty()) {
            throw new AttributeEncodingException("Failed to encode any values for attribute " + attribute.getId());
        }

        final String name = properties.getProperty(PROP_NAME);
        if (Strings.isNullOrEmpty(name)) {
            throw new AttributeEncodingException("Required transcoder property 'name' not found");
        }

        final AttributeDesignator samlAttribute;
        
        if (to.equals(Attribute.class)) {
            if (attributeValues.isEmpty()) {
                throw new AttributeEncodingException("Unable to encode a SAML 1 Attribute with no values");
            }
            
            samlAttribute = attributeBuilder.buildObject();
            ((Attribute) samlAttribute).getAttributeValues().addAll(attributeValues);
        } else if (to.equals(AttributeDesignator.class)) {
            samlAttribute = designatorBuilder.buildObject();
            log.warn("Lossy conversion to AttributeDesignator");
        } else {
            throw new AttributeEncodingException("Unsupported target object type: " + to.getName());
        }

        samlAttribute.setAttributeName(name);
        samlAttribute.setAttributeNamespace(
                properties.getProperty(PROP_NAMESPACE, SAMLConstants.SAML1_ATTR_NAMESPACE_URI));
        
        return samlAttribute;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected IdPAttribute buildIdPAttribute(
            @Nullable final ProfileRequestContext profileRequestContext, @Nonnull final AttributeDesignator attribute,
            @Nonnull final Properties properties,
            @Nonnull @NonnullElements final List<IdPAttributeValue<?>> attributeValues)
                    throws AttributeDecodingException {
        
        final String id = properties.getProperty(AttributeTranscoderRegistry.PROP_ID);
        if (Strings.isNullOrEmpty(id)) {
            throw new AttributeDecodingException("Required transcoder property 'id' not found");
        }
        
        final IdPAttribute idpAttribute;
        if (attribute instanceof Attribute) {
            if (!((Attribute) attribute).getAttributeValues().isEmpty() && attributeValues.isEmpty()) {
                throw new AttributeDecodingException("Failed to decode any values for attribute "
                        + attribute.getAttributeName());
            }
            idpAttribute = new IdPAttribute(id);
        } else {
            idpAttribute = new IdPRequestedAttribute(id);
        }
        
        idpAttribute.setValues(attributeValues);
        
        return idpAttribute;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected Iterable<XMLObject> getValues(@Nonnull final AttributeDesignator input) {
        return input instanceof Attribute ? ((Attribute) input).getAttributeValues() : Collections.emptyList();
    }

    /** A function to produce a "canonical" name for a SAML 1 {@link AttributeDesignator} for transcoding rules. */
    public static class NamingFunction implements Function<AttributeDesignator,String> {

        /** {@inheritDoc} */
        @Nullable public String apply(@Nullable final AttributeDesignator input) {
            
            if (input == null || input.getAttributeName() == null || input.getAttributeNamespace() == null) {
                return null;
            }
            
            final StringBuilder builder = new StringBuilder();
            builder.append("SAML1:{").append(input.getAttributeNamespace()).append('}')
                .append(input.getAttributeName());
            return builder.toString();
        }

    }

}