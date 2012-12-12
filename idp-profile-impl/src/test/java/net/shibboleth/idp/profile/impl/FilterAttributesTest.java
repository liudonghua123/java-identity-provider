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

package net.shibboleth.idp.profile.impl;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.shibboleth.idp.attribute.Attribute;
import net.shibboleth.idp.attribute.AttributeContext;
import net.shibboleth.idp.attribute.AttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.filtering.AttributeFilterContext;
import net.shibboleth.idp.attribute.filtering.AttributeFilterPolicy;
import net.shibboleth.idp.attribute.filtering.AttributeFilteringEngine;
import net.shibboleth.idp.attribute.filtering.AttributeValueFilterPolicy;
import net.shibboleth.idp.attribute.filtering.MockAttributeValueMatcher;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.EventIds;
import net.shibboleth.idp.profile.ProfileRequestContext;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.relyingparty.RelyingPartyContext;

import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.common.base.Predicates;
import com.google.common.collect.Lists;

/** {@link FilterAttributes} unit test. */
public class FilterAttributesTest {

    /** Test that the action errors out properly if there is no relying party context. */
    @Test public void testNoRelyingPartyContext() throws Exception {
        ProfileRequestContext profileCtx = new ProfileRequestContext();

        AttributeFilteringEngine engine = new AttributeFilteringEngine("test", null);

        FilterAttributes action = new FilterAttributes(engine);
        action.setId("test");
        action.initialize();

        Event result = action.doExecute(null, null, profileCtx);

        ActionTestingSupport.assertEvent(result, EventIds.INVALID_RELYING_PARTY_CTX);
    }

    /** Test that the action errors out properly if there is no attribute context. */
    @Test public void testNoAttributeContext() throws Exception {
        ProfileRequestContext profileCtx = new RequestContextBuilder().buildProfileRequestContext();

        AttributeFilteringEngine engine = new AttributeFilteringEngine("test", null);

        FilterAttributes action = new FilterAttributes(engine);
        action.setId("test");
        action.initialize();

        Event result = action.doExecute(null, null, profileCtx);

        ActionTestingSupport.assertEvent(result, EventIds.INVALID_ATTRIBUTE_CTX);
    }

    /** Test that the action proceeds properly if there are no attributes to filter . */
    @Test public void testNoAttributes() throws Exception {
        ProfileRequestContext profileCtx = new RequestContextBuilder().buildProfileRequestContext();

        AttributeContext attribCtx = new AttributeContext();
        profileCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attribCtx);

        AttributeFilteringEngine engine = new AttributeFilteringEngine("test", null);

        FilterAttributes action = new FilterAttributes(engine);
        action.setId("test");
        action.initialize();

        Event result = action.doExecute(null, null, profileCtx);

        ActionTestingSupport.assertProceedEvent(result);
    }

    /** Test that the action filters attributes and proceeds properly while auto-creating a filter context. */
    @Test public void testFilterAttributesAutoCreateFilterContext() throws Exception {
        Attribute attribute1 = new Attribute("attribute1");
        attribute1.setValues(Lists.<AttributeValue> newArrayList(new StringAttributeValue("one"),
                new StringAttributeValue("two")));

        Attribute attribute2 = new Attribute("attribute2");
        attribute2.setValues(Lists.<AttributeValue> newArrayList(new StringAttributeValue("a"),
                new StringAttributeValue("b")));

        List<Attribute> attributes = Arrays.asList(attribute1, attribute2);

        MockAttributeValueMatcher attribute1Matcher = new MockAttributeValueMatcher();
        attribute1Matcher.setMatchingAttribute("attribute1");
        attribute1Matcher.setMatchingValues(null);

        AttributeValueFilterPolicy attribute1Policy = new AttributeValueFilterPolicy();
        attribute1Policy.setAttributeId("attribute1");
        attribute1Policy.setValueMatcher(attribute1Matcher);

        AttributeFilterPolicy policy =
                new AttributeFilterPolicy("attribute1Policy", Predicates.alwaysTrue(),
                        Lists.newArrayList(attribute1Policy));

        AttributeFilteringEngine engine = new AttributeFilteringEngine("engine", Lists.newArrayList(policy));
        engine.initialize();

        ProfileRequestContext profileCtx = new RequestContextBuilder().buildProfileRequestContext();

        AttributeContext attributeCtx = new AttributeContext();
        attributeCtx.setAttributes(attributes);
        profileCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeCtx);

        FilterAttributes action = new FilterAttributes(engine);
        action.setId("test");
        action.initialize();

        Event result = action.doExecute(null, null, profileCtx);

        ActionTestingSupport.assertProceedEvent(result);

        // The attribute filter context should be removed by the filter attributes action.
        Assert.assertNull(profileCtx.getSubcontext(RelyingPartyContext.class).getSubcontext(
                AttributeFilterContext.class));

        AttributeContext resultAttributeCtx =
                profileCtx.getSubcontext(RelyingPartyContext.class).getSubcontext(AttributeContext.class);
        Assert.assertNotNull(resultAttributeCtx);

        Map<String, Attribute> resultAttributes = resultAttributeCtx.getAttributes();
        Assert.assertEquals(resultAttributes.size(), 1);

        Set<AttributeValue> resultAttributeValue = resultAttributes.get("attribute1").getValues();
        Assert.assertEquals(resultAttributeValue.size(), 2);
        Assert.assertTrue(resultAttributeValue.contains(new StringAttributeValue("one")));
        Assert.assertTrue(resultAttributeValue.contains(new StringAttributeValue("two")));
    }

    /** Test that the action filters attributes and proceeds properly with an existing filter context. */
    @Test public void testFilterAttributesExistingFilterContext() throws Exception {
        Attribute attribute1 = new Attribute("attribute1");
        attribute1.setValues(Lists.<AttributeValue> newArrayList(new StringAttributeValue("one"),
                new StringAttributeValue("two")));

        Attribute attribute2 = new Attribute("attribute2");
        attribute2.setValues(Lists.<AttributeValue> newArrayList(new StringAttributeValue("a"),
                new StringAttributeValue("b")));

        List<Attribute> attributes = Arrays.asList(attribute1, attribute2);

        MockAttributeValueMatcher attribute1Matcher = new MockAttributeValueMatcher();
        attribute1Matcher.setMatchingAttribute("attribute1");
        attribute1Matcher.setMatchingValues(null);

        AttributeValueFilterPolicy attribute1Policy = new AttributeValueFilterPolicy();
        attribute1Policy.setAttributeId("attribute1");
        attribute1Policy.setValueMatcher(attribute1Matcher);

        AttributeFilterPolicy policy =
                new AttributeFilterPolicy("attribute1Policy", Predicates.alwaysTrue(),
                        Lists.newArrayList(attribute1Policy));

        AttributeFilteringEngine engine = new AttributeFilteringEngine("engine", Lists.newArrayList(policy));
        engine.initialize();

        ProfileRequestContext profileCtx = new RequestContextBuilder().buildProfileRequestContext();

        AttributeContext attributeCtx = new AttributeContext();
        attributeCtx.setAttributes(attributes);
        profileCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeCtx);

        AttributeFilterContext attributeFilterCtx = new AttributeFilterContext();
        profileCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeFilterCtx);

        FilterAttributes action = new FilterAttributes(engine);
        action.setId("test");
        action.initialize();

        Event result = action.doExecute(null, null, profileCtx);

        ActionTestingSupport.assertProceedEvent(result);

        // The attribute filter context should be removed by the filter attributes action.
        Assert.assertNull(profileCtx.getSubcontext(RelyingPartyContext.class).getSubcontext(
                AttributeFilterContext.class));

        AttributeContext resultAttributeCtx =
                profileCtx.getSubcontext(RelyingPartyContext.class).getSubcontext(AttributeContext.class);
        Assert.assertNotNull(resultAttributeCtx);

        Map<String, Attribute> resultAttributes = resultAttributeCtx.getAttributes();
        Assert.assertEquals(resultAttributes.size(), 1);

        Set<AttributeValue> resultAttributeValue = resultAttributes.get("attribute1").getValues();
        Assert.assertEquals(resultAttributeValue.size(), 2);
        Assert.assertTrue(resultAttributeValue.contains(new StringAttributeValue("one")));
        Assert.assertTrue(resultAttributeValue.contains(new StringAttributeValue("two")));
    }

    /** Test that action returns the proper event if the attributes are not able to be filtered. */
    @Test public void testUnableToFilterAttributes() throws Exception {
        Attribute attribute1 = new MockUncloneableAttribute("attribute1");
        attribute1.setValues(Lists.<AttributeValue> newArrayList(new StringAttributeValue("one"),
                new StringAttributeValue("two")));

        List<Attribute> attributes = Arrays.asList(attribute1);

        MockAttributeValueMatcher attribute1Matcher = new MockAttributeValueMatcher();
        attribute1Matcher.setMatchingAttribute("attribute1");
        attribute1Matcher.setMatchingValues(null);

        AttributeValueFilterPolicy attribute1Policy = new AttributeValueFilterPolicy();
        attribute1Policy.setAttributeId("attribute1");
        attribute1Policy.setValueMatcher(attribute1Matcher);

        AttributeFilterPolicy policy =
                new AttributeFilterPolicy("attribute1Policy", Predicates.alwaysTrue(),
                        Lists.newArrayList(attribute1Policy));

        AttributeFilteringEngine engine = new AttributeFilteringEngine("engine", Lists.newArrayList(policy));
        engine.initialize();

        ProfileRequestContext profileCtx = new RequestContextBuilder().buildProfileRequestContext();

        AttributeContext attributeCtx = new AttributeContext();
        attributeCtx.setAttributes(attributes);
        profileCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeCtx);

        AttributeFilterContext attributeFilterCtx = new AttributeFilterContext();
        profileCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeFilterCtx);

        FilterAttributes action = new FilterAttributes(engine);
        action.setId("test");
        action.initialize();

        Event result = action.doExecute(null, null, profileCtx);

        ActionTestingSupport.assertEvent(result, FilterAttributes.UNABLE_FILTER_ATTRIBS);
    }

    /** {@link Attribute} which always throws a {@link CloneNotSupportedException}. */
    private class MockUncloneableAttribute extends Attribute {

        /**
         * Constructor.
         * 
         * @param attributeId
         */
        public MockUncloneableAttribute(String attributeId) {
            super(attributeId);
        }

        /** Always throws exception. */
        public Attribute clone() throws CloneNotSupportedException {
            throw new CloneNotSupportedException();
        }
    }
}
