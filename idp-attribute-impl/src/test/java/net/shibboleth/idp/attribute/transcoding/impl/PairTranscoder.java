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

package net.shibboleth.idp.attribute.transcoding.impl;

import java.util.Collections;
import java.util.Properties;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.attribute.AttributeDecodingException;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.transcoding.AbstractAttributeTranscoder;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Sample transcoder for tests. 
 */
public class PairTranscoder extends AbstractAttributeTranscoder<Pair<String,Object>> {

    /** {@inheritDoc} */
    public String getEncodedName(Properties properties) {
        if (properties.containsKey("name")) {
            return "{Pair}" + properties.getProperty("name");
        } else {
            return null;
        }
    }

    /** {@inheritDoc} */
    public Pair<String,Object> encode(ProfileRequestContext profileRequestContext, IdPAttribute attribute, Properties properties)
            throws AttributeEncodingException {
        
        final String name = StringSupport.trimOrNull(properties.getProperty("name"));
        if (name == null) {
            throw new AttributeEncodingException("No name property");
        }
        
        if (attribute.getValues().isEmpty() || !canEncodeValue(attribute, attribute.getValues().get(0))) {
            return new Pair<>(name, null);
        } else {
            return new Pair<>(name, attribute.getValues().get(0).getValue());
        }
    }

    /** {@inheritDoc} */
    public IdPAttribute decode(ProfileRequestContext profileRequestContext, Pair<String,Object> input, Properties properties)
            throws AttributeDecodingException {
       
        final String id = StringSupport.trimOrNull(properties.getProperty(AttributeTranscoderRegistry.PROP_ID));
        if (id == null) {
            throw new AttributeDecodingException("No id property");
        }
        
        final IdPAttribute idattr = new IdPAttribute(id);
        
        if (input.getSecond() instanceof String) {
            idattr.setValues(Collections.singletonList(StringAttributeValue.valueOf((String) input.getSecond())));
        }
        
        return idattr;
    }

    /** {@inheritDoc} */
    protected boolean canEncodeValue(IdPAttribute idpAttribute, IdPAttributeValue value) {
        return value instanceof StringAttributeValue;
    }
    
}