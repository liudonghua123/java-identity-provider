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

package net.shibboleth.idp.saml.impl.profile.saml2;

import java.util.Locale;

import org.opensaml.profile.ProfileException;
import org.opensaml.profile.action.ActionTestingSupport;
import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.config.SecurityConfiguration;
import net.shibboleth.idp.relyingparty.RelyingPartyConfiguration;
import net.shibboleth.idp.relyingparty.RelyingPartyContext;
import net.shibboleth.idp.saml.profile.config.saml2.BrowserSSOProfileConfiguration;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.context.NoSuchMessageException;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.test.MockRequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.Lists;

/** {@link AddStatusToResponse} unit test. */
public class AddStatusToResponseTest extends OpenSAMLInitBaseTestCase {

    private MockRequestContext springRequestContext; 
    
    private ProfileRequestContext<Object,Response> prc;
    
    private AddResponseShell addResponse;
    
    private AddStatusToResponse action;
    
    @BeforeMethod public void setUp() throws ComponentInitializationException, ProfileException {
        springRequestContext = (MockRequestContext) new RequestContextBuilder().buildRequestContext();
        prc = (ProfileRequestContext) springRequestContext.getConversationScope().get(ProfileRequestContext.BINDING_KEY);
        
        final BrowserSSOProfileConfiguration profileConfig = new BrowserSSOProfileConfiguration();
        profileConfig.setSecurityConfiguration(new SecurityConfiguration());
        prc.setOutboundMessageContext(new MessageContext<Response>());
        final RelyingPartyContext rpCtx = prc.getSubcontext(RelyingPartyContext.class, true);
        rpCtx.setProfileConfig(profileConfig);

        addResponse = new AddResponseShell();
        addResponse.initialize();
        addResponse.execute(prc);
        
        action = new AddStatusToResponse();
    }

    @Test public void testMinimal() throws ProfileException, ComponentInitializationException {
        action.initialize();
        
        action.execute(springRequestContext);
        ActionTestingSupport.assertProceedEvent(prc);
        
        final Response response = prc.getOutboundMessageContext().getMessage();

        final Status status = response.getStatus();
        Assert.assertNotNull(status);
        
        Assert.assertNotNull(status.getStatusCode());
        Assert.assertEquals(status.getStatusCode().getValue(), StatusCode.RESPONDER_URI);
        Assert.assertNull(status.getStatusCode().getStatusCode());
        
        Assert.assertNull(status.getStatusMessage());
    }

    @Test public void testMultiStatus() throws ProfileException, ComponentInitializationException {
        action.setStatusCodes(Lists.newArrayList(StatusCode.REQUESTER_URI, StatusCode.REQUEST_VERSION_DEPRECATED_URI));
        action.initialize();
        
        action.execute(springRequestContext);
        ActionTestingSupport.assertProceedEvent(prc);
        
        final Response response = prc.getOutboundMessageContext().getMessage();

        final Status status = response.getStatus();
        Assert.assertNotNull(status);
        
        Assert.assertNotNull(status.getStatusCode());
        Assert.assertEquals(status.getStatusCode().getValue(), StatusCode.REQUESTER_URI);
        Assert.assertNotNull(status.getStatusCode().getStatusCode());
        Assert.assertEquals(status.getStatusCode().getStatusCode().getValue(), StatusCode.REQUEST_VERSION_DEPRECATED_URI);
        Assert.assertNull(status.getStatusCode().getStatusCode().getStatusCode());
        
        Assert.assertNull(status.getStatusMessage());
    }

    @Test public void testFixedMessage() throws ProfileException, ComponentInitializationException {
        action.setStatusMessage("Foo");
        action.setStatusMessageFromEvent(false);
        action.initialize();
        
        action.execute(springRequestContext);
        ActionTestingSupport.assertProceedEvent(prc);
        
        final Response response = prc.getOutboundMessageContext().getMessage();

        final Status status = response.getStatus();
        Assert.assertNotNull(status);
        Assert.assertEquals(status.getStatusMessage().getMessage(), "Foo");
    }

    @Test public void testMappedMessage() throws ProfileException, ComponentInitializationException {
        
        action.setStatusMessage("Foo");
        action.setStatusMessageFromEvent(true);
        action.setMessageSource(new MockMessageSource());
        action.initialize();

        RelyingPartyConfiguration rpConfig = new RelyingPartyConfiguration();
        rpConfig.setId("foo");
        rpConfig.setResponderId("foo");
        rpConfig.setDetailedErrors(true);
        rpConfig.initialize();
        prc.getSubcontext(RelyingPartyContext.class, false).setConfiguration(rpConfig);
        
        action.execute(springRequestContext);
        ActionTestingSupport.assertProceedEvent(prc);
        
        final Response response = prc.getOutboundMessageContext().getMessage();

        Status status = response.getStatus();
        Assert.assertNotNull(status);
        Assert.assertEquals(status.getStatusMessage().getMessage(), "Foo");

        springRequestContext.setCurrentEvent(new Event(this, "Mappable"));
        action.execute(springRequestContext);
        ActionTestingSupport.assertProceedEvent(prc);

        status = response.getStatus();
        Assert.assertNotNull(status);
        Assert.assertEquals(status.getStatusMessage().getMessage(), "Mapped");

        rpConfig = new RelyingPartyConfiguration();
        rpConfig.setId("foo");
        rpConfig.setResponderId("foo");
        rpConfig.setDetailedErrors(false);
        rpConfig.initialize();
        prc.getSubcontext(RelyingPartyContext.class, false).setConfiguration(rpConfig);
        
        action.execute(springRequestContext);
        ActionTestingSupport.assertProceedEvent(prc);

        status = response.getStatus();
        Assert.assertNotNull(status);
        Assert.assertEquals(status.getStatusMessage().getMessage(), "Foo");
    }
    
    private class MockMessageSource implements MessageSource {

        /** {@inheritDoc} */
        public String getMessage(String code, Object[] args, String defaultMessage, Locale locale) {
            if (code.equals("Mappable")) {
                return "Mapped";
            } else {
                return defaultMessage;
            }
        }

        /** {@inheritDoc} */
        public String getMessage(String code, Object[] args, Locale locale) throws NoSuchMessageException {
            if (code.equals("Mappable")) {
                return "Mapped";
            }
            throw new NoSuchMessageException("No such message");
        }

        /** {@inheritDoc} */
        public String getMessage(MessageSourceResolvable resolvable, Locale locale) throws NoSuchMessageException {
            if (resolvable.getCodes()[0].equals("Mappable")) {
                return "Mapped";
            }
            throw new NoSuchMessageException("No such message");
        }
        
    }
    
}