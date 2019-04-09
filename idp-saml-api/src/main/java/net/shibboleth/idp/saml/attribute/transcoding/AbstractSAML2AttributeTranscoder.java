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

import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.Attribute;

import com.google.common.base.Strings;

/**
 * Base class for transcoders that operate on a SAML 2 {@link Attribute}.
 * 
 * @param <EncodedType> the type of data that can be handled by the transcoder
 */
public abstract class AbstractSAML2AttributeTranscoder<EncodedType extends IdPAttributeValue> extends
        AbstractSAMLAttributeTranscoder<Attribute,EncodedType> {

    /** A friendly, human readable, name for the attribute. */
    @Nonnull @NotEmpty public static final String PROP_FRIENDLY_NAME = "friendlyName";

    /** The format of the attribute name. */
    @Nonnull @NotEmpty public static final String PROP_NAME_FORMAT = "nameFormat";

    /** Builder used to construct {@link Attribute} objects. */
    @Nonnull private final SAMLObjectBuilder<Attribute> attributeBuilder;

    /** Constructor. */
    public AbstractSAML2AttributeTranscoder() {
        attributeBuilder =
                (SAMLObjectBuilder<Attribute>) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(
                        Attribute.TYPE_NAME);
        if (attributeBuilder == null) {
            throw new ConstraintViolationException("SAML 2 Attribute builder is unavailable");
        }
    }

    
    /** {@inheritDoc} */
    @Nullable public String getEncodedName(@Nonnull final Properties properties) {
        
        try {
            // SAML 2 naming should be based on only what needs to be available from the properties alone.
            return new NamingFunction().apply(buildAttribute(null, null, properties, Collections.emptyList()));
        } catch (final AttributeEncodingException e) {
            return null;
        }
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected Attribute buildAttribute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final IdPAttribute attribute, @Nonnull final Properties properties,
            @Nonnull @NonnullElements final List<XMLObject> attributeValues) throws AttributeEncodingException {

        final String name = properties.getProperty(PROP_NAME);
        if (Strings.isNullOrEmpty(name)) {
            throw new AttributeEncodingException("Required transcoder property 'name' not found");
        }
                
        final Attribute samlAttribute = attributeBuilder.buildObject();
        samlAttribute.setName(name);
        samlAttribute.setNameFormat(properties.getProperty(PROP_NAME_FORMAT, Attribute.URI_REFERENCE));
        samlAttribute.getAttributeValues().addAll(attributeValues);
        
        final String friendlyName = properties.getProperty(PROP_FRIENDLY_NAME, attribute.getId());
        if (!friendlyName.isBlank()) {
            samlAttribute.setFriendlyName(friendlyName);
        }
        
        return samlAttribute;
    }

    /**
     * A function to produce a "canonical" name for a SAML 2.0 {@link Attribute} for transcoding rules.
     */
    public static class NamingFunction implements Function<Attribute,String> {

        /** {@inheritDoc} */
        @Nullable public String apply(@Nullable final Attribute input) {
            
            if (input == null || input.getName() == null) {
                return null;
            }
            
            String format = input.getNameFormat();
            if (format == null) {
                format = Attribute.UNSPECIFIED;
            }
            
            final StringBuilder builder = new StringBuilder();
            builder.append('{').append(format).append('}').append(input.getName());
            return builder.toString();
        }

    }

}