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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateIDTokenAuthorizedParty}.
 */
public class ValidateIDTokenAuthorizedPartyTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateIDTokenAuthorizedParty action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateIDTokenAuthorizedParty();
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action with single audience.
     * 
     * @throws Exception
     */
    @Test
    public void testSingleAudience() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIDConnectContext oidcCtx = authCtx.getSubcontext(OpenIDConnectContext.class, true);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        oidcCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }

    /**
     * Runs action without clientID as azp.
     * 
     * @throws Exception
     */
    @Test
    public void testNotAuthorized() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIDConnectContext oidcCtx = authCtx.getSubcontext(OpenIDConnectContext.class, true);
        final List<String> audience = new ArrayList<>();
        audience.add(DEFAULT_CLIENT_ID);
        audience.add("anotherOne");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("azp", DEFAULT_CLIENT_ID);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(null, DEFAULT_ISSUER, audience, claims);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        oidcCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID + "invalid"));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with clientId as azp.
     * 
     * @throws Exception
     */
    @Test
    public void testAuthorized() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIDConnectContext oidcCtx = authCtx.getSubcontext(OpenIDConnectContext.class, true);
        final List<String> audience = new ArrayList<>();
        audience.add(DEFAULT_CLIENT_ID);
        audience.add("anotherOne");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("azp", DEFAULT_CLIENT_ID);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(null, DEFAULT_ISSUER, audience, claims);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        oidcCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
        Assert.assertNull(action.execute(src));
    }
}
