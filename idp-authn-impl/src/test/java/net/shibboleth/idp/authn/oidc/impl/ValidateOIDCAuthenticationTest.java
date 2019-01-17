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

import org.joda.time.DateTime;
import org.mockito.Mockito;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCAuthentication}.
 */
public class ValidateOIDCAuthenticationTest extends AbstractOIDCIDTokenTest {

    /** Action to be tested. */
    private ValidateOIDCAuthentication action;

    /** {@inheritDoc} */
    @Override
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCAuthentication();
    }

    /**
     * Runs action without attempted flow.
     */
    @Test
    public void testMissingFlow() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /** {@inheritDoc} */
    @Test
    public void testNoContext() throws Exception {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        super.testNoContext();
    }

    /** {@inheritDoc} */
    @Test
    public void testUnparseable() throws Exception {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        super.testUnparseable();
    }

    /**
     * Runs action without {@link OIDCTokenResponse}.
     */
    @Test
    public void testNoOidcResponse() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without {@link OIDCTokens} in {@link OIDCTokenResponse}.
     */
    @Test
    public void testNoOidcTokens() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final OIDCTokenResponse oidcTokenResponse = Mockito.mock(OIDCTokenResponse.class);
        Mockito.when(oidcTokenResponse.getOIDCTokens()).thenReturn(null);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without subject in the ID token.
     */
    @Test
    public void testNoSubject() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final OIDCTokenResponse oidcTokenResponse = Mockito.mock(OIDCTokenResponse.class);
        final JWT idToken = Mockito.mock(JWT.class);
        final JWTClaimsSet claimSet = JWTClaimsSet.parse("{ \"mock\" : \"mock\" }");
        Mockito.when(idToken.getJWTClaimsSet()).thenReturn(claimSet);
        final OIDCTokens oidcTokens = new OIDCTokens(idToken, new BearerAccessToken(), new RefreshToken());
        Mockito.when(oidcTokenResponse.getOIDCTokens()).thenReturn(oidcTokens);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action fulfilled requirements.
     */
    @Test
    public void testValid() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().minusSeconds(1).toDate());
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
