
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
