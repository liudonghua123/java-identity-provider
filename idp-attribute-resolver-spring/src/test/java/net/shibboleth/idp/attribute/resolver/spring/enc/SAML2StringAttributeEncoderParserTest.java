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

package net.shibboleth.idp.attribute.resolver.spring.enc;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.Collection;
import java.util.Map;
import java.util.function.Predicate;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.resolver.spring.BaseEncoderDefinitionParserTest;
import net.shibboleth.idp.attribute.resolver.spring.enc.impl.SAML2StringAttributeEncoderParser;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAML2AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.impl.SAML2StringAttributeTranscoder;

/**
 * Test for {@link SAML2StringAttributeEncoderParser}.
 */
public class SAML2StringAttributeEncoderParserTest extends BaseEncoderDefinitionParserTest {
  
    protected void testWithProperties(final boolean activation, final Boolean encodeType) {
        
        final Collection<Map<String,Object>> rules =
                getAttributeTranscoderRule("resolver/saml2String.xml", activation, encodeType);
        assertEquals(rules.size(), 1);
        
        final Map<String,Object> rule = rules.iterator().next();

        assertTrue(rule.get(AttributeTranscoderRegistry.PROP_TRANSCODER) instanceof SAML2StringAttributeTranscoder);
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME), "Saml2String_ATTRIBUTE_NAME");
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME_FORMAT), "Saml2String_ATTRIBUTE_NAME_FORMAT");
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_FRIENDLY_NAME), "Saml2String_ATTRIBUTE_FRIENDLY_NAME");
        assertEquals(activation, ((Predicate) rule.get(AttributeTranscoderRegistry.PROP_CONDITION)).test(null));
        checkEncodeType(rule, encodeType!=null ? encodeType : false);
    }
    
    @Test public void defaultCase() {
        final Collection<Map<String,Object>> rules =
                getAttributeTranscoderRule("resolver/saml2StringDefault.xml");
        assertEquals(rules.size(), 1);
        
        final Map<String,Object> rule = rules.iterator().next();

        assertTrue(rule.get(AttributeTranscoderRegistry.PROP_TRANSCODER) instanceof SAML2StringAttributeTranscoder);
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME), "Saml2StringName");
        assertNull(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME_FORMAT));
        assertNull(rule.get(AbstractSAML2AttributeTranscoder.PROP_FRIENDLY_NAME));
        assertFalse(((Predicate) rule.get(AttributeTranscoderRegistry.PROP_CONDITION)).test(null));
        checkEncodeType(rule, true);
    }
    
    @Test(expectedExceptions={BeanDefinitionStoreException.class,})  public void noName() {
        getAttributeTranscoderRule("resolver/saml2StringNoName.xml");
    }
    
}