
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
import net.shibboleth.idp.authn.oidc.context.OpenIdConnectContext;
import net.shibboleth.idp.authn.oidc.impl.ValidateOIDCIDTokenACR;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenACR}.
 */
public class ValidateOIDCIDTokenACRTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenACR action;

    /** The ACR value. */
    private String acr;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenACR();
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
        authCtx.addSubcontext(new OpenIdConnectContext());
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
        final OpenIdConnectContext suCtx = buildContextWithACR(acrs, null);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final OpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"mock\" : \"mock\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final OpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"acr\" : \"invalid\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final OpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"acr\" : \"" + acr + "\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
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
        final OpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"acr\" : \"" + acr + "\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        Assert.assertNull(action.execute(src));
    }

    /**
     * Helper for building {@link OpenIdConnectContext}.
     * 
     * @param acrs
     * @param jwt
     * @return
     * @throws Exception
     */
    protected OpenIdConnectContext buildContextWithACR(final List<ACR> acrs, final String jwt)
            throws Exception {
        final OpenIdConnectContext suCtx = new OpenIdConnectContext();
        suCtx.setAcrs(acrs);
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
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        return suCtx;
    }
}
