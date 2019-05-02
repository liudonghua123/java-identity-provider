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

import static org.testng.Assert.*;

import java.util.Collection;
import java.util.Map;
import java.util.function.Predicate;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.resolver.spring.BaseAttributeDefinitionParserTest;
import net.shibboleth.idp.attribute.resolver.spring.enc.impl.SAML2ScopedStringAttributeEncoderParser;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAML2AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.impl.SAML2ScopedStringAttributeTranscoder;

/**
 * Test for {@link SAML2ScopedStringAttributeEncoderParser}.
 */
public class SAML2ScopedStringAttributeEncoderParserTest extends BaseAttributeDefinitionParserTest {

    @Test public void resolver() {
        boolTest(true);
        boolTest(false);
    }

    private void boolTest(boolean value) {
        final Collection<Map<String,Object>> rules =
                getAttributeTranscoderRule("resolver/saml2Scoped.xml", Collection.class, value?"true":"false");
        assertEquals(rules.size(), 1);
        
        final Map<String,Object> rule = rules.iterator().next();

        assertTrue(rule.get(AttributeTranscoderRegistry.PROP_TRANSCODER) instanceof SAML2ScopedStringAttributeTranscoder);
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME), "ATTRIBUTE_NAME");
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME_FORMAT), "ATTRIBUTE_NAME_FORMAT");
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_FRIENDLY_NAME), "ATTRIBUTE_FRIENDLY_NAME");
        assertEquals(rule.get(SAML2ScopedStringAttributeTranscoder.PROP_SCOPE_TYPE), "attribute");
        assertEquals(rule.get(SAML2ScopedStringAttributeTranscoder.PROP_SCOPE_ATTR_NAME), "scopeAttrib");
        assertEquals(rule.get(SAML2ScopedStringAttributeTranscoder.PROP_SCOPE_DELIMITER), "###");
        assertEquals(value, ((Predicate) rule.get(AttributeTranscoderRegistry.PROP_CONDITION)).test(null));
    }
    
    @Test public void defaultCase() {
        final Collection<Map<String,Object>> rules =
                getAttributeTranscoderRule("resolver/saml2ScopedDefault.xml", Collection.class);
        assertEquals(rules.size(), 1);
        
        final Map<String,Object> rule = rules.iterator().next();

        assertTrue(rule.get(AttributeTranscoderRegistry.PROP_TRANSCODER) instanceof SAML2ScopedStringAttributeTranscoder);
        assertEquals(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME), "name");
        assertNull(rule.get(AbstractSAML2AttributeTranscoder.PROP_NAME_FORMAT));
        assertNull(rule.get(AbstractSAML2AttributeTranscoder.PROP_FRIENDLY_NAME));
        assertNull(rule.get(SAML2ScopedStringAttributeTranscoder.PROP_SCOPE_TYPE));
        assertNull(rule.get(SAML2ScopedStringAttributeTranscoder.PROP_SCOPE_ATTR_NAME));
        assertNull(rule.get(SAML2ScopedStringAttributeTranscoder.PROP_SCOPE_DELIMITER));
        assertFalse(((Predicate) rule.get(AttributeTranscoderRegistry.PROP_CONDITION)).test(null));
    }
    
    @Test(expectedExceptions={BeanDefinitionStoreException.class,})  public void noName() {
        getAttributeTranscoderRule("resolver/saml2ScopedNoName.xml", Collection.class);
    }
}
