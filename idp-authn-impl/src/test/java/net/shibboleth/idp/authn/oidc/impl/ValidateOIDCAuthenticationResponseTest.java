/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
import net.shibboleth.idp.authn.oidc.context.SocialUserOpenIdConnectContext;
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
     * Runs action without {@link SocialUserOpenIdConnectContext}.
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setAuthenticationResponseURI(getHttpServletRequest(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setAuthenticationResponseURI(getHttpServletRequest(state));
        suCtx.setState(State.parse("invalid"));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setAuthenticationResponseURI(getHttpServletRequest(state));
        suCtx.setState(State.parse(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationSuccessResponse successResponse = suCtx.getAuthenticationSuccessResponse();
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setAuthenticationResponseURI(getHttpServletRequest(state, "request_not_supported", null));
        suCtx.setState(State.parse(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setAuthenticationResponseURI(getHttpServletRequest(state, "request_not_supported", "mockReason"));
        suCtx.setState(State.parse(state));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
