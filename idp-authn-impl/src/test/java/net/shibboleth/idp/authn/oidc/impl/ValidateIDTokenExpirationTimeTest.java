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
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateIDTokenExpirationTime}.
 */
public class ValidateIDTokenExpirationTimeTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateIDTokenExpirationTime action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateIDTokenExpirationTime();
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action with expired OIDC token.
     */
    @Test
    public void testExpired() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().minusSeconds(1).toDate());
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with OIDC token expiring in the future.
     */
    @Test
    public void testValid() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().plusMinutes(5).toDate());
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
