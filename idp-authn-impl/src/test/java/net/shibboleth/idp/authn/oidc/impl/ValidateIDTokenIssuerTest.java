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

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateIDTokenIssuer}.
 */
public class ValidateIDTokenIssuerTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateIDTokenIssuer action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateIDTokenIssuer();
    }

    @Override
    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action with invalid issuer.
     */
    @Test
    public void testInvalid() throws Exception {
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        final OIDCProviderMetadata oidcMetadata = buildOidcMetadata(DEFAULT_ISSUER + ".invalid");
        oidcCtx.setoIDCProviderMetadata(oidcMetadata);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with valid issuer.
     */
    @Test
    public void testValid() throws Exception {
        action.initialize();
        final OpenIDConnectContext oidcCtx = new OpenIDConnectContext();
        final OIDCProviderMetadata oidcMetadata = buildOidcMetadata(DEFAULT_ISSUER);
        oidcCtx.setoIDCProviderMetadata(oidcMetadata);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        oidcCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(oidcCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
