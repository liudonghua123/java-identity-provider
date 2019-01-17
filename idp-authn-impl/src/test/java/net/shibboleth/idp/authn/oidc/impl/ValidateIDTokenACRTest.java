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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.mockito.Mockito;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.authn.oidc.impl.ValidateIDTokenACR;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateIDTokenACR}.
 */
public class ValidateIDTokenACRTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateIDTokenACR action;

    /** The ACR value. */
    private String acr;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateIDTokenACR();
        acr = "mockAcr";
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action without requested acr.
     */
    @Test
    public void testNoAcr() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        authCtx.addSubcontext(new OpenIDConnectContext());
        Assert.assertNull(action.execute(src));
    }

    /**
     * Runs action with unparseable response.
     */
    @Test
    public void testUnparseable() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final OpenIDConnectContext oidcCtx = buildContextWithACR(acrs, null);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without acrs in {@link OIDCTokenResponse} even though they're requested.
     */
    @Test
    public void testNoResponseAcr() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final OpenIDConnectContext oidcCtx = buildContextWithACR(acrs, "{ \"mock\" : \"mock\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without acrs in {@link OIDCTokenResponse} even though they're requested.
     */
    @Test
    public void testNoMatchingAcr() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final OpenIDConnectContext oidcCtx = buildContextWithACR(acrs, "{ \"acr\" : \"invalid\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with acr in {@link OIDCTokenResponse} as single requested.
     */
    @Test
    public void testSuccessSingle() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final OpenIDConnectContext oidcCtx = buildContextWithACR(acrs, "{ \"acr\" : \"" + acr + "\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        Assert.assertNull(action.execute(src));
    }

    /**
     * Runs action with acr in {@link OIDCTokenResponse} as one of three requested.
     */
    @Test
    public void testSuccessTriple() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        acrs.add(new ACR("second"));
        acrs.add(new ACR("third"));
        final OpenIDConnectContext oidcCtx = buildContextWithACR(acrs, "{ \"acr\" : \"" + acr + "\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        Assert.assertNull(action.execute(src));
    }

    /**
     * Helper for building {@link OpenIDConnectContext}.
     * 
     * @param acrs
     * @param jwt
     * @return
     * @throws Exception
     */
    protected OpenIDConnectContext buildContextWithACR(final List<ACR> acrs, final String jwt)
            throws Exception {
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        oidcCtx.setAcrs(acrs);
        final OIDCTokenResponse oidcTokenResponse = Mockito.mock(OIDCTokenResponse.class);
        final JWT idToken = Mockito.mock(JWT.class);
        if (jwt == null) {
            Mockito.when(idToken.getJWTClaimsSet()).thenThrow(new ParseException("mockException", 1));
        } else {
            final JWTClaimsSet claimSet = JWTClaimsSet.parse(jwt);
            Mockito.when(idToken.getJWTClaimsSet()).thenReturn(claimSet);
        }
        final OIDCTokens oidcTokens = new OIDCTokens(idToken, new BearerAccessToken(), new RefreshToken());
        Mockito.when(oidcTokenResponse.getOIDCTokens()).thenReturn(oidcTokens);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        return oidcCtx;
    }
}
