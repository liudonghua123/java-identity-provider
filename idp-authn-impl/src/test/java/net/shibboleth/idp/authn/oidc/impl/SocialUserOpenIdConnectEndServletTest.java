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

import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;

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
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;
import net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl;
import net.shibboleth.idp.authn.oidc.context.SocialUserOpenIdConnectContext;

/**
 * Unit tests for {@link SocialUserOpenIdConnectEndServlet}.
 */
public class SocialUserOpenIdConnectEndServletTest {

    /** The servlet to be tested. */
    SocialUserOpenIdConnectEndServlet servlet;

    /** The conversation key. */
    String conversationKey;

    /**
     * Init tests.
     * 
     * @throws Exception
     */
    @BeforeTest
    public void initTests() throws Exception {
        servlet = new SocialUserOpenIdConnectEndServlet();
        MockServletConfig mockConfig = new MockServletConfig();
        servlet.init(mockConfig);
        conversationKey = "mockKey";
    }

    /**
     * Run servlet without conversation key set.
     * 
     * @throws Exception
     */
    @Test
    public void testNoConversationKey() throws Exception {
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        Assert.assertTrue(SocialUserOpenIdConnectStartServletTest.runService(servlet, httpRequest,
                new MockHttpServletResponse()));
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
        Assert.assertTrue(SocialUserOpenIdConnectStartServletTest.runService(servlet, httpRequest,
                new MockHttpServletResponse()));
    }

    /**
     * Run servlet without {@link SocialUserOpenIdConnectContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testNoSocialUserContext() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.getSession().setAttribute(SocialUserOpenIdConnectStartServlet.SESSION_ATTR_FLOWKEY,
                conversationKey);
        Assert.assertTrue(SocialUserOpenIdConnectStartServletTest.runService(servlet, httpRequest,
                new MockHttpServletResponse()));
    }

    /**
     * Run servlet with invalid authentication response URI.
     * 
     * @throws Exception
     */
    @Test
    public void testInvalidAuthnResponseUri() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.getSession().setAttribute(SocialUserOpenIdConnectStartServlet.SESSION_ATTR_FLOWKEY,
                conversationKey);
        final SocialUserOpenIdConnectContext suOidcCtx = Mockito.mock(SocialUserOpenIdConnectContext.class);
        Mockito.doThrow(new URISyntaxException("mockException", "mock")).when(suOidcCtx)
                .setAuthenticationResponseURI(httpRequest);
        httpRequest.getSession().setAttribute(SocialUserOpenIdConnectStartServlet.SESSION_ATTR_SUCTX, suOidcCtx);
        Assert.assertTrue(SocialUserOpenIdConnectStartServletTest.runService(servlet, httpRequest,
                new MockHttpServletResponse()));
    }

    /**
     * Run servlet successfully through.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccess() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.getSession().setAttribute(SocialUserOpenIdConnectStartServlet.SESSION_ATTR_FLOWKEY,
                conversationKey);
        httpRequest.getSession().setAttribute(SocialUserOpenIdConnectStartServlet.SESSION_ATTR_SUCTX,
                new SocialUserOpenIdConnectContext());
        final ProfileRequestContext<?, ?> ctx = new ProfileRequestContext<>();
        httpRequest.getSession().setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey,
                new ExternalAuthenticationImpl(ctx));
        final AuthenticationContext authnCtx = ctx.getSubcontext(AuthenticationContext.class, true);
        final ExternalAuthenticationContext externalCtx =
                authnCtx.getSubcontext(ExternalAuthenticationContext.class, true);
        final String url = "https://mock.example.org/";
        externalCtx.setFlowExecutionUrl(url);
        final AuthenticationFlowDescriptor flow = new AuthenticationFlowDescriptor();
        flow.setId("mock");
        authnCtx.setAttemptedFlow(flow);
        final MockHttpServletResponse httpResponse = new MockHttpServletResponse();
        Assert.assertFalse(SocialUserOpenIdConnectStartServletTest.runService(servlet, httpRequest, httpResponse));
        Assert.assertEquals(httpResponse.getRedirectedUrl(), url);
    }
}
