
package net.shibboleth.idp.authn.oidc.impl;

import org.joda.time.DateTime;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.SocialUserOpenIdConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenExpirationTime}.
 */
public class ValidateOIDCIDTokenExpirationTimeTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenExpirationTime action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenExpirationTime();
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().minusSeconds(1).toDate());
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().plusMinutes(5).toDate());
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
