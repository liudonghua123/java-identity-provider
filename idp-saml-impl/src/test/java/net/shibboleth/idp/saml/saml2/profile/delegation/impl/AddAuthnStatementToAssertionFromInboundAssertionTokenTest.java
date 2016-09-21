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

package net.shibboleth.idp.saml.saml2.profile.delegation.impl;

import javax.annotation.Nullable;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.saml.saml2.profile.SAML2ActionTestingSupport;
import net.shibboleth.idp.saml.saml2.profile.delegation.LibertySSOSContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLAssertTestNG;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Function;
import com.google.common.base.Predicates;

/**
 *
 */
public class AddAuthnStatementToAssertionFromInboundAssertionTokenTest extends OpenSAMLInitBaseTestCase {
    
    private AddAuthnStatementToAssertionFromInboundAssertionToken action;
    
    private RequestContext rc;
    private ProfileRequestContext prc;
    
    private Assertion delegatedAssertion;
    
    private AuthnStatement delegatedAuthnStatement;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        Response response = SAML2ActionTestingSupport.buildResponse();
        response.getAssertions().add(SAML2ActionTestingSupport.buildAssertion());
        
        rc = new RequestContextBuilder()
            .setInboundMessage(SAML2ActionTestingSupport.buildAuthnRequest())
            .setOutboundMessage(response)
            .buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(rc);
        
        delegatedAssertion = SAML2ActionTestingSupport.buildAssertion();
        
        delegatedAuthnStatement = SAML2ActionTestingSupport.buildAuthnStatement();
        delegatedAssertion.getAuthnStatements().add(delegatedAuthnStatement);
        
        prc.getSubcontext(LibertySSOSContext.class, true).setAttestedToken(delegatedAssertion);
        
        action = new AddAuthnStatementToAssertionFromInboundAssertionToken();
    }
    
    @Test
    public void testSuccess() throws ComponentInitializationException, MarshallingException {
        action.initialize();
        final Event result = action.execute(rc);
        ActionTestingSupport.assertProceedEvent(result);
        
        Assertion newAssertion = ((Response)prc.getOutboundMessageContext().getMessage()).getAssertions().get(0);
        Assert.assertFalse(newAssertion.getAuthnStatements().isEmpty());
        XMLAssertTestNG.assertXMLEqual(
                XMLObjectSupport.marshall(delegatedAuthnStatement).getOwnerDocument(),
                XMLObjectSupport.marshall(newAssertion.getAuthnStatements().get(0)).getOwnerDocument());
    }
    
    @Test
    public void testActivationCondition() throws ComponentInitializationException {
        prc.removeSubcontext(LibertySSOSContext.class); // This would otherwise cause failure
        action.setActivationCondition(Predicates.alwaysFalse());
        
        action.initialize();
        final Event result = action.execute(rc);
        ActionTestingSupport.assertProceedEvent(result);
    }
    
    @Test
    public void testNoLibertyContext() throws ComponentInitializationException {
        prc.removeSubcontext(LibertySSOSContext.class);
        
        action.initialize();
        final Event result = action.execute(rc);
        ActionTestingSupport.assertEvent(result, EventIds.INVALID_PROFILE_CTX);
    }
    
    @Test
    public void testNoDelegatedAssertion() throws ComponentInitializationException {
        prc.getSubcontext(LibertySSOSContext.class).setAttestedToken(null);
        
        action.initialize();
        final Event result = action.execute(rc);
        ActionTestingSupport.assertEvent(result, EventIds.INVALID_PROFILE_CTX);
    }
    
    @Test
    public void testNoDelegatedAuthnStatement() throws ComponentInitializationException {
        delegatedAssertion.getAuthnStatements().clear();
        
        action.initialize();
        final Event result = action.execute(rc);
        ActionTestingSupport.assertEvent(result, EventIds.INVALID_PROFILE_CTX);
    }
    
    @Test
    public void testNoAssertionToModify() throws ComponentInitializationException {
        action.setAssertionLookupStrategy(new Function<ProfileRequestContext, Assertion>() {
            @Nullable public Assertion apply(@Nullable ProfileRequestContext input) {
                return null;
            }});
        
        action.initialize();
        final Event result = action.execute(rc);
        ActionTestingSupport.assertEvent(result, EventIds.INVALID_MSG_CTX);
    }

}
