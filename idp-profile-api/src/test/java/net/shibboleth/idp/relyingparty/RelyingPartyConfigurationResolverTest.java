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

package net.shibboleth.idp.relyingparty;

import java.util.ArrayList;
import java.util.Iterator;

import net.shibboleth.idp.profile.ProfileRequestContext;

import org.opensaml.util.criteria.StaticResponseEvaluableCriterion;
import org.testng.Assert;
import org.testng.annotations.Test;

/** Unit test for {@link RelyingPartyConfigurationResolver}. */
public class RelyingPartyConfigurationResolverTest {

    @Test
    public void testConstruction() {
        RelyingPartyConfigurationResolver resolver;

        RelyingPartyConfiguration anonConfig =
                new RelyingPartyConfiguration("anonymous", StaticResponseEvaluableCriterion.FALSE_RESPONSE, null);

        ArrayList<RelyingPartyConfiguration> rpConfigs = new ArrayList<RelyingPartyConfiguration>();
        rpConfigs.add(new RelyingPartyConfiguration("one", StaticResponseEvaluableCriterion.TRUE_RESPONSE, null));
        rpConfigs.add(new RelyingPartyConfiguration("two", StaticResponseEvaluableCriterion.FALSE_RESPONSE, null));
        rpConfigs.add(new RelyingPartyConfiguration("three", StaticResponseEvaluableCriterion.TRUE_RESPONSE, null));

        resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        resolver.setAnonymousRelyingPartyConfiguration(anonConfig);
        resolver.setRelyingPartyConfigurations(rpConfigs);
        Assert.assertEquals(resolver.getId(), "test");
        Assert.assertSame(resolver.getAnonymousRelyingPartyConfiguration(), anonConfig);
        Assert.assertEquals(resolver.getRelyingPartyConfigurations().size(), 3);

        resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        resolver.setAnonymousRelyingPartyConfiguration(anonConfig);
        Assert.assertEquals(resolver.getId(), "test");
        Assert.assertSame(resolver.getAnonymousRelyingPartyConfiguration(), anonConfig);
        Assert.assertEquals(resolver.getRelyingPartyConfigurations().size(), 0);

        resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        Assert.assertEquals(resolver.getId(), "test");
        Assert.assertNull(resolver.getAnonymousRelyingPartyConfiguration());
        Assert.assertEquals(resolver.getRelyingPartyConfigurations().size(), 0);
    }

    @Test
    public void testResolve() throws Exception {
        ProfileRequestContext requestContext = new ProfileRequestContext();

        RelyingPartyConfiguration config1 =
                new RelyingPartyConfiguration("one", StaticResponseEvaluableCriterion.TRUE_RESPONSE, null);
        RelyingPartyConfiguration config2 =
                new RelyingPartyConfiguration("two", StaticResponseEvaluableCriterion.FALSE_RESPONSE, null);
        RelyingPartyConfiguration config3 =
                new RelyingPartyConfiguration("three", StaticResponseEvaluableCriterion.TRUE_RESPONSE, null);

        ArrayList<RelyingPartyConfiguration> rpConfigs = new ArrayList<RelyingPartyConfiguration>();
        rpConfigs.add(config1);
        rpConfigs.add(config2);
        rpConfigs.add(config3);

        RelyingPartyConfigurationResolver resolver = new RelyingPartyConfigurationResolver();
        resolver.setId("test");
        resolver.setRelyingPartyConfigurations(rpConfigs);

        Iterable<RelyingPartyConfiguration> results = resolver.resolve(requestContext);
        Assert.assertNotNull(results);

        Iterator<RelyingPartyConfiguration> resultItr = results.iterator();
        Assert.assertTrue(resultItr.hasNext());
        Assert.assertSame(resultItr.next(), config1);
        Assert.assertTrue(resultItr.hasNext());
        Assert.assertSame(resultItr.next(), config3);
        Assert.assertFalse(resultItr.hasNext());

        RelyingPartyConfiguration result = resolver.resolveSingle(requestContext);
        Assert.assertSame(result, config1);

        results = resolver.resolve(null);
        Assert.assertNotNull(results);

        resultItr = results.iterator();
        Assert.assertFalse(resultItr.hasNext());

        result = resolver.resolveSingle(null);
        Assert.assertNull(result);
    }
}