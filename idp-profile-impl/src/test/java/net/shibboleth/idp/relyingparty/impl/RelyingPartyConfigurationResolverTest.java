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

package net.shibboleth.idp.relyingparty.impl;

import java.util.ArrayList;
import java.util.Iterator;

import net.shibboleth.idp.relyingparty.RelyingPartyConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.common.base.Predicates;
import com.google.common.collect.Lists;

/** Unit test for {@link RelyingPartyConfigurationResolver}. */
public class RelyingPartyConfigurationResolverTest {

    @Test public void testConstruction() throws ComponentInitializationException {
        RelyingPartyConfiguration one = new RelyingPartyConfiguration();
        one.setId("one");
        one.setResponderId("foo");
        one.setDetailedErrors(true);
        one.initialize();

        RelyingPartyConfiguration two = new RelyingPartyConfiguration();
        two.setId("two");
        two.setResponderId("foo");
        two.setDetailedErrors(true);
        two.setActivationCondition(Predicates.<ProfileRequestContext>alwaysFalse());
        two.initialize();

        RelyingPartyConfiguration three = new RelyingPartyConfiguration();
        three.setId("three");
        three.setResponderId("foo");
        three.setDetailedErrors(true);
        three.initialize();
        
        ArrayList<RelyingPartyConfiguration> rpConfigs = Lists.newArrayList(one, two, three);

        RelyingPartyConfigurationResolver resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        resolver.setRelyingPartyConfigurations(rpConfigs);
        Assert.assertEquals(resolver.getId(), "test");
        Assert.assertEquals(resolver.getRelyingPartyConfigurations().size(), 3);

        resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        Assert.assertEquals(resolver.getId(), "test");
        Assert.assertEquals(resolver.getRelyingPartyConfigurations().size(), 0);

        resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        Assert.assertEquals(resolver.getId(), "test");
        Assert.assertEquals(resolver.getRelyingPartyConfigurations().size(), 0);
    }

    @Test public void testResolve() throws Exception {
        ProfileRequestContext requestContext = new ProfileRequestContext();

        RelyingPartyConfiguration one = new RelyingPartyConfiguration();
        one.setId("one");
        one.setResponderId("foo");
        one.setDetailedErrors(true);
        one.initialize();

        RelyingPartyConfiguration two = new RelyingPartyConfiguration();
        two.setId("two");
        two.setResponderId("foo");
        two.setDetailedErrors(true);
        two.setActivationCondition(Predicates.<ProfileRequestContext>alwaysFalse());
        two.initialize();

        RelyingPartyConfiguration three = new RelyingPartyConfiguration();
        three.setId("three");
        three.setResponderId("foo");
        three.setDetailedErrors(true);
        three.initialize();
        
        ArrayList<RelyingPartyConfiguration> rpConfigs = Lists.newArrayList(one, two, three);

        RelyingPartyConfigurationResolver resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        resolver.setRelyingPartyConfigurations(rpConfigs);
        resolver.initialize();

        Iterable<RelyingPartyConfiguration> results = resolver.resolve(requestContext);
        Assert.assertNotNull(results);

        Iterator<RelyingPartyConfiguration> resultItr = results.iterator();
        Assert.assertTrue(resultItr.hasNext());
        Assert.assertSame(resultItr.next(), one);
        Assert.assertTrue(resultItr.hasNext());
        Assert.assertSame(resultItr.next(), three);
        Assert.assertFalse(resultItr.hasNext());

        RelyingPartyConfiguration result = resolver.resolveSingle(requestContext);
        Assert.assertSame(result, one);

        results = resolver.resolve(null);
        Assert.assertNotNull(results);

        resultItr = results.iterator();
        Assert.assertFalse(resultItr.hasNext());

        result = resolver.resolveSingle(null);
        Assert.assertNull(result);
    }
}