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

package net.shibboleth.idp.authn.oidc.impl;

import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCAuthenticationResponse}.
 */
public class ValidateOIDCAuthenticationResponseTest extends AbstractOIDCIDTokenTest {

    /** Action to be tested. */
    private ValidateOIDCAuthenticationResponse action;

    private String state;

    /** {@inheritDoc} */
    @Override
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCAuthenticationResponse();
        state = "mockState";
    }

    /**
     * Runs action without {@link OpenIDConnectContext}.
     */
    @Test
    public void testNoContext() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without authentication response uri set.
     */
    @Test
    public void testNoResponseUri() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);

    }

    /** {@inheritDoc} */
    @Test
    public void testUnparseable() throws Exception {
        // Different structure than in abstract class, skipping this method
    }

    /**
     * Runs action without setting state to the context.
     */
    @Test
    public void testNoState() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        oidcCtx.setAuthenticationResponseURI(getHttpServletRequest(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with mismatching state in context and request.
     */
    @Test
    public void testStateMismatch() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        oidcCtx.setAuthenticationResponseURI(getHttpServletRequest(state));
        oidcCtx.setState(State.parse("invalid"));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with matching states in request and context.
     */
    @Test
    public void testStateMatch() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        oidcCtx.setAuthenticationResponseURI(getHttpServletRequest(state));
        oidcCtx.setState(State.parse(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationSuccessResponse successResponse = oidcCtx.getAuthenticationSuccessResponse();
        Assert.assertNotNull(successResponse);
        Assert.assertEquals(successResponse.getState(), State.parse(state));
    }

    /**
     * Runs action with error in the response.
     */
    @Test
    public void testErrorResponse() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        oidcCtx.setAuthenticationResponseURI(getHttpServletRequest(state, "request_not_supported", null));
        oidcCtx.setState(State.parse(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with error code and description in the response.
     */
    @Test
    public void testErrorResponseWithDescription() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        oidcCtx.setAuthenticationResponseURI(getHttpServletRequest(state, "request_not_supported", "mockReason"));
        oidcCtx.setState(State.parse(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Helper method for initializing servlet request with state parameter.
     * 
     * @param state
     * @return
     */
    protected MockHttpServletRequest getHttpServletRequest(final String state) {
        return getHttpServletRequest(state, null, null);
    }

    /**
     * Helper method for initializing servlet request with state and error parameters.
     * 
     * @param state
     * @param errorCode
     * @param errorDesc
     * @return
     */
    protected MockHttpServletRequest getHttpServletRequest(final String state, final String errorCode,
            final String errorDesc) {
        final MockHttpServletRequest httpRequest = Mockito.mock(MockHttpServletRequest.class);
        Mockito.when(httpRequest.getRequestURL()).thenReturn(new StringBuffer("https://example.org/mock"));
        if (state == null) {
            Mockito.when(httpRequest.getQueryString()).thenReturn(null);
            return httpRequest;
        }
        if (errorCode == null) {
            Mockito.when(httpRequest.getQueryString()).thenReturn("state=" + state);
        } else {
            Mockito.when(httpRequest.getQueryString())
                    .thenReturn("state=" + state + "&error=" + errorCode + "&error_description=" + errorDesc);
        }
        return httpRequest;
    }
}
