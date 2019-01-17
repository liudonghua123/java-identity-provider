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
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

/**
 * Unit tests for {@link OpenIDConnectEndServlet}.
 */
public class OpenIDConnectEndServletTest {

    /** The servlet to be tested. */
    OpenIDConnectEndServlet servlet;

    /** The conversation key. */
    String conversationKey;

    /**
     * Init tests.
     * 
     * @throws Exception
     */
    @BeforeTest
    public void initTests() throws Exception {
        servlet = new OpenIDConnectEndServlet();
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
        Assert.assertTrue(OpenIDConnectStartServletTest.runService(servlet, httpRequest,
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
        Assert.assertTrue(OpenIDConnectStartServletTest.runService(servlet, httpRequest,
                new MockHttpServletResponse()));
    }

    /**
     * Run servlet without {@link OpenIDConnectContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testNoUserContext() throws Exception {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.getSession().setAttribute(OpenIDConnectStartServlet.SESSION_ATTR_FLOWKEY,
                conversationKey);
        Assert.assertTrue(OpenIDConnectStartServletTest.runService(servlet, httpRequest,
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
        httpRequest.getSession().setAttribute(OpenIDConnectStartServlet.SESSION_ATTR_FLOWKEY,
                conversationKey);
        final OpenIDConnectContext suOidcCtx = Mockito.mock(OpenIDConnectContext.class);
        Mockito.doThrow(new URISyntaxException("mockException", "mock")).when(suOidcCtx)
                .setAuthenticationResponseURI(httpRequest);
        httpRequest.getSession().setAttribute(OpenIDConnectStartServlet.SESSION_ATTR_SUCTX, suOidcCtx);
        Assert.assertTrue(OpenIDConnectStartServletTest.runService(servlet, httpRequest,
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
        httpRequest.getSession().setAttribute(OpenIDConnectStartServlet.SESSION_ATTR_FLOWKEY,
                conversationKey);
        httpRequest.getSession().setAttribute(OpenIDConnectStartServlet.SESSION_ATTR_SUCTX,
                new OpenIDConnectContext());
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
        Assert.assertFalse(OpenIDConnectStartServletTest.runService(servlet, httpRequest, httpResponse));
        Assert.assertEquals(httpResponse.getRedirectedUrl(), url);
    }
}
