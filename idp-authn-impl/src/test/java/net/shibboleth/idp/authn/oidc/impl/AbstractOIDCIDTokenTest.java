package net.shibboleth.idp.authn.oidc.impl;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.mockito.Mockito;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;


import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.BaseAuthenticationContextTest;
import net.shibboleth.idp.authn.oidc.context.OpenIdConnectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Abstract test case sharing tests for OIDC token validation in {@link OpenIdConnectContext}.
 */
public abstract class AbstractOIDCIDTokenTest extends BaseAuthenticationContextTest {

    public static final String DEFAULT_ISSUER = "mockIssuer";

    public static final String DEFAULT_CLIENT_ID = "mockClientId";

    public boolean nullifyIdToken;

    /**
     * Returns the action to be tested.
     * 
     * @return
     */
    protected abstract AbstractProfileAction<?, ?> getAction();

    /**
     * Runs action without {@link OpenIdConnectContext}.
     */
    @Test
    public void testNoContext() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Helper method for building {@link OIDCTokenResponse} with a given expiration time.
     * 
     * @param expirationTime The expiration time.
     * @return
     */
    protected OIDCTokenResponse getOidcTokenResponse(final Date expirationTime) {
        return getOidcTokenResponse(expirationTime, null);
    }

    /**
     * Helper method for building {@link OIDCTokenResponse} with a given issuer.
     * 
     * @param issuer
     * @return
     */
    protected OIDCTokenResponse getOidcTokenResponse(final String issuer) {
        return getOidcTokenResponse(null, issuer);
    }

    /**
     * Helper method for building {@link OIDCTokenResponse} with a given expiration time and issuer.
     * 
     * @param expirationTime
     * @param issuer
     * @return
     */
    protected static OIDCTokenResponse getOidcTokenResponse(final Date expirationTime, final String issuer) {
        return getOidcTokenResponse(expirationTime, issuer, null, null);
    }

    /**
     * Helper method for building {@link OIDCTokenResponse} with a given expiration time and issuer.
     * 
     * @param expirationTime
     * @param issuer
     * @param audience
     * @param claims
     * @return
     */
    protected static OIDCTokenResponse getOidcTokenResponse(final Date expirationTime, final String issuer,
            final List<String> audience, final Map<String, Object> claims) {
        final JWTClaimsSet claimsSet = buildClaimsSet(expirationTime, issuer, audience, claims);
        final PlainJWT plainJwt = new PlainJWT(claimsSet);
        final AccessToken accessToken = new BearerAccessToken();
        final RefreshToken refreshToken = new RefreshToken();
        final OIDCTokens oidcTokens = new OIDCTokens(plainJwt, accessToken, refreshToken);
        final OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(oidcTokens);
        return oidcTokenResponse;
    }

    /**
     * Helper method for building {@link JWTClaimSet} with a given expiration time and issuer.
     * 
     * @param expirationTime
     * @param issuer
     * @param audience
     * @param claims
     * @return
     */
    protected static JWTClaimsSet buildClaimsSet(final Date expirationTime, final String issuer,
            final List<String> audience, final Map<String, Object> claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().subject("mockUser").issuer(issuer)
                .expirationTime(expirationTime).claim("http://example.org/mock", true);
        if (audience == null) {
            builder = builder.audience(DEFAULT_CLIENT_ID);
        } else {
            builder = builder.audience(audience);
        }
        if (claims != null) {
            for (final String claim : claims.keySet()) {
                builder = builder.claim(claim, claims.get(claim));
            }
        }
        return builder.build();
    }

    /**
     * Helper method for building {@link OIDCProviderMetadata} with the given issuer.
     * 
     * @param issuer The issuer.
     * @return
     * @throws Exception
     */
    protected OIDCProviderMetadata buildOidcMetadata(final String issuer) throws Exception {
        final List<SubjectType> subjectTypes = new ArrayList<>();
        subjectTypes.add(SubjectType.PUBLIC);
        return new OIDCProviderMetadata(new Issuer(issuer), subjectTypes, new URI("https://mock.org/"));
    }

    /**
     * Runs action with unparseable OIDC token.
     */

    @SuppressWarnings("unchecked")
    @Test
    public void testUnparseable() throws Exception {
        // TODO: replace with new relevant or target the correct ones only
        final AccessToken accessToken = new BearerAccessToken();
        final RefreshToken refreshToken = new RefreshToken();
        final JWT jwt = Mockito.mock(JWT.class);
        Mockito.when(jwt.getJWTClaimsSet()).thenThrow(java.text.ParseException.class);
        final OIDCTokens oidcTokens = new OIDCTokens(jwt, accessToken, refreshToken);
        final OIDCTokenResponse oidcTokenResponse = new OIDCTokenResponse(oidcTokens);
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final OpenIdConnectContext suCtx = new OpenIdConnectContext();
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        if (nullifyIdToken) {
            suCtx.setIDToken(null);
        }
        suCtx.setoIDCProviderMetadata(buildOidcMetadata(DEFAULT_ISSUER));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);

    }

}
