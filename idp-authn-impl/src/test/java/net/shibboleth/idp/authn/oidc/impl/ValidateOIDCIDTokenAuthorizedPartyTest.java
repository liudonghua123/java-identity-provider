
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
import net.shibboleth.idp.authn.oidc.context.OpenIdConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenAuthorizedParty}.
 */
public class ValidateOIDCIDTokenAuthorizedPartyTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenAuthorizedParty action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenAuthorizedParty();
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
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        suCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
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
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        final List<String> audience = new ArrayList<>();
        audience.add(DEFAULT_CLIENT_ID);
        audience.add("anotherOne");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("azp", DEFAULT_CLIENT_ID);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(null, DEFAULT_ISSUER, audience, claims);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        suCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID + "invalid"));
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
        final OpenIdConnectContext suCtx = authCtx.getSubcontext(OpenIdConnectContext.class, true);
        final List<String> audience = new ArrayList<>();
        audience.add(DEFAULT_CLIENT_ID);
        audience.add("anotherOne");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("azp", DEFAULT_CLIENT_ID);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(null, DEFAULT_ISSUER, audience, claims);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        suCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
        Assert.assertNull(action.execute(src));
    }
}
