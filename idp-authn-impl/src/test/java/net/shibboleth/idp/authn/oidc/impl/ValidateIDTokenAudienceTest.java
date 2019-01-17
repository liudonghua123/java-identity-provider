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
 * Unit tests for {@link ValidateIDTokenAudience}.
 */
public class ValidateIDTokenAudienceTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateIDTokenAudience action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateIDTokenAudience();
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    @Test
    public void testNotInAudience() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIDConnectContext oidcCtx = authCtx.getSubcontext(OpenIDConnectContext.class, true);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        oidcCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID + "invalid"));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    @Test
    public void testInAudience() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIDConnectContext oidcCtx = authCtx.getSubcontext(OpenIDConnectContext.class, true);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        oidcCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }

}
