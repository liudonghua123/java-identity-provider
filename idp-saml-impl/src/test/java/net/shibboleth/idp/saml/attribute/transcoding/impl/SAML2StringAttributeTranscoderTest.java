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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.ByteAttributeValue;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.IdPRequestedAttribute;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.TranscoderSupport;
import net.shibboleth.idp.attribute.transcoding.impl.AttributeTranscoderRegistryImpl;
import net.shibboleth.idp.attribute.transcoding.impl.TranscodingRule;
import net.shibboleth.idp.saml.attribute.transcoding.AbstractSAML2AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.SAML2AttributeTranscoder;
import net.shibboleth.idp.saml.attribute.transcoding.SAMLAttributeTranscoder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/** {@link SAML2StringAttributeTranscoder} unit test. */
public class SAML2StringAttributeTranscoderTest extends OpenSAMLInitBaseTestCase {

    private AttributeTranscoderRegistryImpl registry;
    
    private XMLObjectBuilder<XSString> stringBuilder;

    private SAMLObjectBuilder<Attribute> attributeBuilder;

    private SAMLObjectBuilder<RequestedAttribute> reqAttributeBuilder;

    private final static String ATTR_NAME = "foo";
    private final static String ATTR_NAMEFORMAT = "Namespace";
    private final static String ATTR_FRIENDLYNAME = "friendly";
    private final static String STRING_1 = "Value The First";
    private final static String STRING_2 = "Second string the value is";

    @BeforeClass public void setUp() throws ComponentInitializationException {
        
        stringBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory().<XSString>getBuilderOrThrow(XSString.TYPE_NAME);
        
        attributeBuilder = (SAMLObjectBuilder<Attribute>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<Attribute>getBuilderOrThrow(
                        Attribute.TYPE_NAME);
        reqAttributeBuilder = (SAMLObjectBuilder<RequestedAttribute>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<RequestedAttribute>getBuilderOrThrow(
                        RequestedAttribute.TYPE_NAME);
        
        registry = new AttributeTranscoderRegistryImpl();
        registry.setId("test");

        final SAML2StringAttributeTranscoder transcoder = new SAML2StringAttributeTranscoder();
        transcoder.initialize();
        
        registry.setNamingRegistry(Collections.singletonMap(transcoder.getEncodedType(),
                new AbstractSAML2AttributeTranscoder.NamingFunction()));
        
        final Map<String,Object> ruleset1 = new HashMap<>();
        ruleset1.put(AttributeTranscoderRegistry.PROP_ID, ATTR_NAME);
        ruleset1.put(AttributeTranscoderRegistry.PROP_TRANSCODER, transcoder);
        ruleset1.put(SAMLAttributeTranscoder.PROP_ENCODE_TYPE, true);
        ruleset1.put(SAMLAttributeTranscoder.PROP_NAME, ATTR_NAME);
        ruleset1.put(SAML2AttributeTranscoder.PROP_NAME_FORMAT, ATTR_NAMEFORMAT);
        ruleset1.put(SAML2AttributeTranscoder.PROP_FRIENDLY_NAME, ATTR_FRIENDLYNAME);
        
        registry.setTranscoderRegistry(Collections.singletonList(new TranscodingRule(ruleset1)));
        
        registry.initialize();
    }
    
    @AfterClass public void tearDown() {
        registry.destroy();
        registry = null;
    }

    @Test public void emptyEncode() throws Exception {
        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final Attribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).encode(
                null, inputAttribute, Attribute.class, ruleset);
        
        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getName(), ATTR_NAME);
        Assert.assertEquals(attr.getNameFormat(), ATTR_NAMEFORMAT);
        Assert.assertEquals(attr.getFriendlyName(), ATTR_FRIENDLYNAME);
        Assert.assertTrue(attr.getAttributeValues().isEmpty());
    }

    @Test public void emptyDecode() throws Exception {
        
        final Attribute samlAttribute = attributeBuilder.buildObject();
        samlAttribute.setName(ATTR_NAME);
        samlAttribute.setNameFormat(ATTR_NAMEFORMAT);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(samlAttribute);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final IdPAttribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).decode(null, samlAttribute, ruleset);
        
        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getId(), ATTR_NAME);
        Assert.assertTrue(attr.getValues().isEmpty());
    }

    @Test public void emptyRequestedDecode() throws Exception {
        
        final RequestedAttribute samlAttribute = reqAttributeBuilder.buildObject();
        samlAttribute.setName(ATTR_NAME);
        samlAttribute.setNameFormat(ATTR_NAMEFORMAT);
        samlAttribute.setIsRequired(true);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(samlAttribute);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final IdPAttribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).decode(null, samlAttribute, ruleset);
        
        Assert.assertTrue(attr instanceof IdPRequestedAttribute);
        Assert.assertEquals(attr.getId(), ATTR_NAME);
        Assert.assertTrue(((IdPRequestedAttribute) attr).getIsRequired());
        Assert.assertTrue(attr.getValues().isEmpty());
    }
    
    @Test(expectedExceptions = {AttributeEncodingException.class,}) public void inappropriate() throws Exception {
        final int[] intArray = {1, 2, 3, 4};
        final Collection<IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}), new IdPAttributeValue<Object>() {
                    @Override
                    public Object getValue() {
                        return intArray;
                    }
                    @Override
                    public String getDisplayValue() {
                        return intArray.toString();
                    }
                });

        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);
        inputAttribute.setValues(values);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        TranscoderSupport.<Attribute>getTranscoder(ruleset).encode(null, inputAttribute, Attribute.class, ruleset);
    }
    
    @Test public void single() throws Exception {
        final Collection<IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}), new StringAttributeValue(STRING_1));

        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);
        inputAttribute.setValues(values);
        
        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final Attribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).encode(
                null, inputAttribute, Attribute.class, ruleset);

        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getName(), ATTR_NAME);
        Assert.assertEquals(attr.getNameFormat(), ATTR_NAMEFORMAT);
        Assert.assertEquals(attr.getFriendlyName(), ATTR_FRIENDLYNAME);

        final List<XMLObject> children = attr.getOrderedChildren();

        Assert.assertEquals(children.size(), 1, "Encoding one entry");

        final XMLObject child = children.get(0);

        Assert.assertEquals(child.getElementQName(), AttributeValue.DEFAULT_ELEMENT_NAME,
                "Attribute Value not inside <AttributeValue/>");

        Assert.assertTrue(child instanceof XSString, "Child of result attribute should be a string");

        final XSString childAsString = (XSString) child;

        Assert.assertEquals(childAsString.getValue(), STRING_1);
    }

    @Test public void singleRequested() throws Exception {
        final Collection<IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}), new StringAttributeValue(STRING_1));

        final IdPRequestedAttribute inputAttribute = new IdPRequestedAttribute(ATTR_NAME);
        inputAttribute.setRequired(true);
        inputAttribute.setValues(values);
        
        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();

        final RequestedAttribute attr = TranscoderSupport.<RequestedAttribute>getTranscoder(ruleset).encode(
                null, inputAttribute, RequestedAttribute.class, ruleset);

        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getName(), ATTR_NAME);
        Assert.assertEquals(attr.getNameFormat(), ATTR_NAMEFORMAT);
        Assert.assertEquals(attr.getFriendlyName(), ATTR_FRIENDLYNAME);
        Assert.assertTrue(attr.isRequired());

        final List<XMLObject> children = attr.getOrderedChildren();

        Assert.assertEquals(children.size(), 1, "Encoding one entry");

        final XMLObject child = children.get(0);

        Assert.assertEquals(child.getElementQName(), AttributeValue.DEFAULT_ELEMENT_NAME,
                "Attribute Value not inside <AttributeValue/>");

        Assert.assertTrue(child instanceof XSString, "Child of result attribute should be a string");

        final XSString childAsString = (XSString) child;

        Assert.assertEquals(childAsString.getValue(), STRING_1);
    }
    
    @Test public void singleDecode() throws Exception {
                
        final XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        stringValue.setValue(STRING_1);
        
        final Attribute samlAttribute = attributeBuilder.buildObject();
        samlAttribute.setName(ATTR_NAME);
        samlAttribute.setNameFormat(ATTR_NAMEFORMAT);
        samlAttribute.getAttributeValues().add(stringValue);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(samlAttribute);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final IdPAttribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).decode(null, samlAttribute, ruleset);
        
        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getId(), ATTR_NAME);
        Assert.assertEquals(attr.getValues().size(), 1);
        Assert.assertEquals(attr.getValues().get(0).getValue().toString(), STRING_1);
    }
    
    
    @Test public void singleRequestedDecode() throws Exception {
        
        final XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        stringValue.setValue(STRING_1);
        
        final RequestedAttribute samlAttribute = reqAttributeBuilder.buildObject();
        samlAttribute.setName(ATTR_NAME);
        samlAttribute.setNameFormat(ATTR_NAMEFORMAT);
        samlAttribute.setIsRequired(true);
        samlAttribute.getAttributeValues().add(stringValue);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(samlAttribute);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final IdPAttribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).decode(null, samlAttribute, ruleset);
        
        Assert.assertTrue(attr instanceof IdPRequestedAttribute);
        Assert.assertEquals(attr.getId(), ATTR_NAME);
        Assert.assertTrue(((IdPRequestedAttribute) attr).getIsRequired());
        Assert.assertEquals(attr.getValues().size(), 1);
        Assert.assertEquals(attr.getValues().get(0).getValue().toString(), STRING_1);
    }
    
    @Test public void multi() throws Exception {
        final Collection<IdPAttributeValue<?>> values =
                Arrays.asList(new ByteAttributeValue(new byte[] {1, 2, 3,}),
                        new StringAttributeValue(STRING_1),
                        new StringAttributeValue(STRING_2),
                        new ScopedStringAttributeValue(STRING_1, STRING_2));

        final IdPAttribute inputAttribute = new IdPAttribute(ATTR_NAME);
        inputAttribute.setValues(values);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(inputAttribute, Attribute.class);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final Attribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).encode(
                null, inputAttribute, Attribute.class, ruleset);

        Assert.assertNotNull(attr);

        final List<XMLObject> children = attr.getOrderedChildren();
        Assert.assertEquals(children.size(), 3, "Encoding three entries");

        for (final XMLObject child: children) {
            Assert.assertTrue(child instanceof XSString, "Child of result attribute should be a string");
            final String childAsString = ((XSString) children.get(0)).getValue();
            Assert.assertTrue(STRING_1.equals(childAsString)||STRING_2.equals(childAsString));
        }
    }

    @Test public void multiDecode() throws Exception {
        
        final XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        stringValue.setValue(STRING_1);

        final XSString stringValue2 = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        stringValue2.setValue(STRING_2);
        
        final Attribute samlAttribute = attributeBuilder.buildObject();
        samlAttribute.setName(ATTR_NAME);
        samlAttribute.setNameFormat(ATTR_NAMEFORMAT);
        samlAttribute.getAttributeValues().add(stringValue);
        samlAttribute.getAttributeValues().add(stringValue2);

        final Collection<Properties> rulesets = registry.getTranscodingProperties(samlAttribute);
        Assert.assertEquals(rulesets.size(), 1);
        final Properties ruleset = rulesets.iterator().next();
        
        final IdPAttribute attr = TranscoderSupport.<Attribute>getTranscoder(ruleset).decode(null, samlAttribute, ruleset);
        
        Assert.assertNotNull(attr);
        Assert.assertEquals(attr.getId(), ATTR_NAME);
        Assert.assertEquals(attr.getValues().size(), 2);
        Assert.assertEquals(attr.getValues().get(0).getValue().toString(), STRING_1);
        Assert.assertEquals(attr.getValues().get(1).getValue().toString(), STRING_2);
    }

}