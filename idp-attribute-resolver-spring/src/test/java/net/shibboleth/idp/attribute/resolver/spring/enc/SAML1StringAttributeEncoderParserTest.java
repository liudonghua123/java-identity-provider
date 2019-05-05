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
import net.shibboleth.idp.attribute.resolver.spring.enc.impl.SAML1StringAttributeEncoderParser;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAML1AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.impl.SAML1StringAttributeTranscoder;

/**
 * Test for {@link SAML1StringAttributeEncoderParser}.
 */
public class SAML1StringAttributeEncoderParserTest extends BaseAttributeDefinitionParserTest {

    @Test public void newNameFormat() {
        newNameFormat(true);
        newNameFormat(false);
    }
    private void newNameFormat(boolean value) {
        final Collection<Map<String,Object>> rules =
                getAttributeTranscoderRule("resolver/saml1String.xml", Collection.class, value?"true":"false");
        assertEquals(rules.size(), 1);
        
        final Map<String,Object> rule = rules.iterator().next();

        assertTrue(rule.get(AttributeTranscoderRegistry.PROP_TRANSCODER) instanceof SAML1StringAttributeTranscoder);
        assertEquals(rule.get(AbstractSAML1AttributeTranscoder.PROP_NAME), "SAML1_STRING_ATTRIBUTE_NAME");
        assertEquals(rule.get(AbstractSAML1AttributeTranscoder.PROP_NAMESPACE), "SAML1_STRING_ATTRIBUTE_NAME_SPACE");
        assertEquals(value, ((Predicate) rule.get(AttributeTranscoderRegistry.PROP_CONDITION)).test(null));
        checkEncodeType(rule, true);
    }

    
    @Test public void defaultCase() {
        final Collection<Map<String,Object>> rules =
                getAttributeTranscoderRule("resolver/saml1StringDefault.xml", Collection.class);
        assertEquals(rules.size(), 1);
        
        final Map<String,Object> rule = rules.iterator().next();

        assertTrue(rule.get(AttributeTranscoderRegistry.PROP_TRANSCODER) instanceof SAML1StringAttributeTranscoder);
        assertEquals(rule.get(AbstractSAML1AttributeTranscoder.PROP_NAME), "ATTRIBUTE");
        assertNull(rule.get(AbstractSAML1AttributeTranscoder.PROP_NAMESPACE));
        assertFalse(((Predicate) rule.get(AttributeTranscoderRegistry.PROP_CONDITION)).test(null));
        checkEncodeType(rule, true);
    }
    
    @Test(expectedExceptions={BeanDefinitionStoreException.class,})  public void noName() {
        getAttributeTranscoderRule("resolver/saml1StringNoName.xml", Collection.class);
    }
    
}