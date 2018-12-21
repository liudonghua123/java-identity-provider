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

import java.io.IOException;
import java.net.URI;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl;
import net.shibboleth.idp.authn.oidc.context.SocialUserOpenIdConnectContext;

/**
 * Unit tests for {@link SocialUserOpenIdConnectStartServlet}.
 */
public class SocialUserOpenIdConnectStartServletTest {

    /** The servlet to be tested. */
    SocialUserOpenIdConnectStartServlet servlet;

    /** The conversation key. */
    String conversationKey;

    /**
     * Init tests.
     * 
     * @throws Exception
     */
    @BeforeTest
    public void initTests() throws Exception {
        servlet = new SocialUserOpenIdConnectStartServlet();
        MockServletConfig mockConfig = new MockServletConfig();
        servlet.init(mockConfig);
        conversationKey = "mockKey";
    }

    /**
     * Run servlet without HttpSession set.
     * 
     * @throws Exception
     */
    @Test
    public void testNoHttpSession() throws Exception {
        HttpServletRequest httpRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpRequest.getSession()).thenReturn(null);
        Assert.assertTrue(runService(servlet, httpRequest, new MockHttpServletResponse()));
    }

    /**
     * Run servlet without conversation key set.
     * 
     * @throws Exception
     */
    @Test
    public void testNoConversationKey() throws Exception {
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        Assert.assertTrue(runService(servlet, httpRequest, new MockHttpServletResponse()));
    }

    /**
     * Run servlet without conversation existing in the session.
     * 
     * @throws Exception
     */
    @Test
    public void testNoConversationInSession() throws Exception {
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        Assert.assertTrue(runService(servlet, httpRequest, new MockHttpServletResponse()));
    }

    /**
     * Run servlet without {@link ProfileRequestContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testNoProfileRequestContext() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        httpRequest.getSession().setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey,
                new MockExternalAuthentication());
        Assert.assertTrue(runService(servlet, httpRequest, new MockHttpServletResponse()));
    }

    /**
     * Run servlet without {@link AuthenticationContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testNoAuthenticationContext() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        final ProfileRequestContext<?, ?> ctx = new ProfileRequestContext<>();
        httpRequest.setAttribute(ProfileRequestContext.BINDING_KEY, ctx);
        httpRequest.getSession().setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey,
                new MockExternalAuthentication());
        Assert.assertTrue(runService(servlet, httpRequest, new MockHttpServletResponse()));
    }

    /**
     * Run servlet without {@link SocialUserOpenIdConnectContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testNoSocialUserContext() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        final ProfileRequestContext<?, ?> ctx = new ProfileRequestContext<>();
        httpRequest.getSession().setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey,
                new ExternalAuthenticationImpl(ctx));
        final AuthenticationContext authnCtx = ctx.getSubcontext(AuthenticationContext.class, true);
        final AuthenticationFlowDescriptor flow = new AuthenticationFlowDescriptor();
        flow.setId("mock");
        authnCtx.setAttemptedFlow(flow);
        Assert.assertTrue(runService(servlet, httpRequest, new MockHttpServletResponse()));
    }

    /**
     * Run servlet with prerequisities met.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccess() throws Exception {
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        final ProfileRequestContext<?, ?> ctx = new ProfileRequestContext<>();
        final AuthenticationContext authnCtx = ctx.getSubcontext(AuthenticationContext.class, true);
        final AuthenticationFlowDescriptor flow = new AuthenticationFlowDescriptor();
        flow.setId("mock");
        authnCtx.setAttemptedFlow(flow);
        final SocialUserOpenIdConnectContext suOidcCtx =
                authnCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        final String redirectUri = "https://mock.example.org";
        suOidcCtx.setAuthenticationRequestURI(new URI(redirectUri));
        httpRequest.getSession().setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey,
                new ExternalAuthenticationImpl(ctx));
        final MockHttpServletResponse httpResponse = new MockHttpServletResponse();
        Assert.assertFalse(runService(servlet, httpRequest, httpResponse));
        Assert.assertEquals(httpResponse.getRedirectedUrl(), redirectUri);
        Assert.assertNotNull(
                httpRequest.getSession().getAttribute(SocialUserOpenIdConnectStartServlet.SESSION_ATTR_SUCTX));
        Assert.assertTrue(httpRequest.getSession().getAttribute(
                SocialUserOpenIdConnectStartServlet.SESSION_ATTR_SUCTX) instanceof SocialUserOpenIdConnectContext);
    }

    /**
     * Runs the given servlet with given request and response objects.
     * 
     * @param httpServlet
     * @param httpRequest
     * @param httpResponse
     * @return True if {@link ServletException} is thrown, false otherwise.
     * @throws IOException
     */
    protected static boolean runService(HttpServlet httpServlet, HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws IOException {
        boolean catched = false;
        try {
            httpServlet.service(httpRequest, httpResponse);
        } catch (ServletException e) {
            catched = true;
        }
        return catched;
    }

    /**
     * Mock class extending {@link ExternalAuthentication}.
     */
    class MockExternalAuthentication extends ExternalAuthentication {

        /** {@inheritDoc} */
        @Override
        protected void doStart(@Nonnull final HttpServletRequest request) throws ExternalAuthenticationException {
            // no op
        }
    }
}
