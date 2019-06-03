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

package net.shibboleth.idp.attribute.resolver.dc.impl;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;

import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.saml.authn.principal.AuthenticationMethodPrincipal;
import net.shibboleth.idp.saml.impl.TestSources;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/** Test for {@link SubjectDataConnector}. */
public class SubjectDataConnectorTest {

    /** Simple result. */
    private static final String SIMPLE_VALUE = "simple";
    

    @Test public void simpleValue() throws ComponentInitializationException, ResolutionException {
        final List<IdPAttributeValue> list = new ArrayList<>(2);
        list.add(new StringAttributeValue(SIMPLE_VALUE));
        list.add(new StringAttributeValue(SIMPLE_VALUE + "2"));
        
        final IdPAttribute attr = new IdPAttribute("wibble");
        attr.setValues(list);

        final SubjectDataConnector defn = new SubjectDataConnector();
        defn.setId("pDAD");
        defn.initialize();

        final AttributeResolutionContext ctx =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final SubjectContext sc = ctx.getParent().getSubcontext(SubjectContext.class, true);
        final Map<String, AuthenticationResult> authnResults = sc.getAuthenticationResults();
        final Subject subject = new Subject();
        subject.getPrincipals().add(new IdPAttributePrincipal(attr));
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE + "2"));
        authnResults.put("one", new AuthenticationResult("1", subject));
        
        
        final Map<String,IdPAttribute> results = defn.resolve(ctx);
        
        assertEquals(1, results.size());
        
        final IdPAttribute copy = results.get("wibble");
        
        assertEquals(copy.getValues().size(), 2);
        assertTrue(copy.getValues().contains(new StringAttributeValue(SIMPLE_VALUE)));
        assertTrue(copy.getValues().contains(new StringAttributeValue(SIMPLE_VALUE + "2")));
    }
    
    @Test public void emptyOk() throws ComponentInitializationException, ResolutionException {

        final SubjectDataConnector defn = new SubjectDataConnector();
        defn.setExportAllAttributes(true);
        defn.setId("pDAD");
        defn.initialize();

        final AttributeResolutionContext ctx =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final SubjectContext sc = ctx.getParent().getSubcontext(SubjectContext.class, true);
        final Map<String, AuthenticationResult> authnResults = sc.getAuthenticationResults();
        final Subject subject = new Subject();
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE + "2"));
        authnResults.put("one", new AuthenticationResult("1", subject));
        
        final Map<String,IdPAttribute> results = defn.resolve(ctx);
        assertTrue(results.isEmpty());
    }

    @Test(expectedExceptions=ResolutionException.class)
    public void emptyError() throws ComponentInitializationException, ResolutionException {

        final SubjectDataConnector defn = new SubjectDataConnector();
        defn.setExportAllAttributes(true);
        defn.setNoResultIsError(true);
        defn.setId("pDAD");
        defn.initialize();

        final AttributeResolutionContext ctx =
                TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                        TestSources.SP_ENTITY_ID);
        final SubjectContext sc = ctx.getParent().getSubcontext(SubjectContext.class, true);
        final Map<String, AuthenticationResult> authnResults = sc.getAuthenticationResults();
        final Subject subject = new Subject();
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE + "2"));
        authnResults.put("one", new AuthenticationResult("1", subject));
        
        defn.resolve(ctx);
    }

}