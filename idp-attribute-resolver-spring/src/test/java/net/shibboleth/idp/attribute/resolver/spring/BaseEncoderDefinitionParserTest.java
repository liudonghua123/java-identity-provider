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

package net.shibboleth.idp.attribute.resolver.spring;

import static net.shibboleth.idp.saml.attribute.transcoding.AbstractSAMLAttributeTranscoder.PROP_ENCODE_TYPE;
import static org.testng.Assert.assertTrue;

import java.util.Collection;
import java.util.Map;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.mock.env.MockPropertySource;
import org.testng.annotations.Test;

/**
 * Base class for testing Attribute Encoding Parsers
 */
public abstract class BaseEncoderDefinitionParserTest extends BaseAttributeDefinitionParserTest {

    protected Collection<Map<String,Object>> getAttributeTranscoderRule(final String fileName) {
        return getAttributeTranscoderRule(fileName, null, null);
    }
    
    protected Collection<Map<String,Object>> getAttributeTranscoderRule(final String fileName,final boolean activation, final Boolean encodeType) {
        final String encodeTypeString;
        if (null == encodeType) {
            encodeTypeString = null;
        } else if (encodeType ){  
            encodeTypeString = "true";
        } else { 
            encodeTypeString = "false";
        } 
        return getAttributeTranscoderRule(fileName, activation?"true":"false", encodeTypeString);
    }

    private Collection<Map<String,Object>> getAttributeTranscoderRule(final String fileName,
            final String activationValue,
            final String encodeType) {

        final GenericApplicationContext context = new GenericApplicationContext();

        if (activationValue != null || encodeType != null) {
            final MockPropertySource mockEnvVars = new MockPropertySource();
            if (activationValue != null) {
                mockEnvVars.setProperty("the.activation.property", activationValue);
            }
            if (encodeType != null) {
                mockEnvVars.setProperty("the.encodeType.property", encodeType);
            }
            final MutablePropertySources propertySources = context.getEnvironment().getPropertySources();
            propertySources.replace(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME, mockEnvVars);
        }

        return getAttributeTranscoderRule(fileName, context);
    }
    
    protected Collection<Map<String,Object>> getAttributeTranscoderRule(final String fileName, final GenericApplicationContext context) {

        setTestContext(context);
        context.setDisplayName("ApplicationContext for encocder");

        return getBean(ENCODER_FILE_PATH + fileName, Collection.class, context);

    }

    static protected void checkEncodeType(final Map<String,Object> rule, boolean expectedValue) {
        final Object encodeType = rule.getOrDefault(PROP_ENCODE_TYPE, Boolean.TRUE);
        assertTrue(encodeType instanceof Boolean);
        assertTrue(encodeType.equals(expectedValue));
    }
    
    abstract protected void testWithProperties(final boolean activation, final Boolean encodeType);
    
    @Test public void values() {
        testWithProperties(true);
        testWithProperties(false);
    }
    
    private void testWithProperties(final boolean activation) {
        testWithProperties(activation, null);
        testWithProperties(activation, true);        
        testWithProperties(activation, false);
    }
}
