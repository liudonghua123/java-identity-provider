
package net.shibboleth.idp.authn.oidc.impl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.joda.time.DateTime;

import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIdConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenAuthenticationTime}.
 */
public class ValidateOIDCIDTokenAuthenticationTimeTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenAuthenticationTime action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenAuthenticationTime();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        // turn force authn on by default, as otherwise action is not run
        authCtx.setForceAuthn(true);
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action without forced authentication.
     * 
     * @throws Exception
     */
    @Test
    public void testNoForceAuthn() throws Exception {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        authCtx.setForceAuthn(false);
        action.initialize();
        Assert.assertNull(action.execute(src));
    }

    /**
     * Runs action with null auth_time.
     * 
     * @throws Exception
     */
    @Test
    public void testNullAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(buildOidcTokenResponse(null));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with auth_time in the future.
     * 
     * @throws Exception
     */
    @Test
    public void testFutureAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(buildOidcTokenResponse(
                new DateTime().plusSeconds((int) (action.getAuthnLifetime() + action.getClockSkew() + 1000)).toDate()));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with expired auth_time.
     * 
     * @throws Exception
     */
    @Test
    public void testExpiredAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(
                buildOidcTokenResponse(new DateTime().minusSeconds((int) action.getClockSkew() + 1000).toDate()));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with valid auth_time.
     * 
     * @throws Exception
     */
    @Test
    public void testValidAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(buildOidcTokenResponse(new DateTime().toDate()));
        Assert.assertNull(action.execute(src));
    }

    protected OIDCTokenResponse buildOidcTokenResponse(final Date authTime) {
        final Map<String, Object> claims = new HashMap<>();
        claims.put("auth_time", authTime);
        return getOidcTokenResponse(null, DEFAULT_ISSUER, null, claims);
    }

}
