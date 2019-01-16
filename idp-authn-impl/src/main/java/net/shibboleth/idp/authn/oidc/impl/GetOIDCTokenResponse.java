
package net.shibboleth.idp.authn.oidc.impl;

import java.io.IOException;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

/**
 * An action that calls the token endpoint and populates the information to {@link OpenIDConnectContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event {@link AuthnEventIds#INVALID_AUTHN_CTX}
 */
@SuppressWarnings("rawtypes")
public class GetOIDCTokenResponse extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(GetOIDCTokenResponse.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull
    final ProfileRequestContext profileRequestContext, @Nonnull
    final AuthenticationContext authenticationContext) {
        log.trace("Entering");
        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (oidcCtx.getIDToken() != null) {
            log.debug("id token exists already, no need to fetch it from token endpoint");
            log.trace("Leaving");
            return;
        }
        final AuthenticationSuccessResponse response = oidcCtx.getAuthenticationSuccessResponse();
        if (response == null) {
            log.info("{} No oidc authentication success response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        final AuthorizationCode code = response.getAuthorizationCode();
        final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, oidcCtx.getRedirectURI());
        final ClientAuthentication clientAuth = new ClientSecretBasic(oidcCtx.getClientID(), oidcCtx.getClientSecret());
        log.debug("{} Using the following token endpoint URI: {}", getLogPrefix(),
                oidcCtx.getoIDCProviderMetadata().getTokenEndpointURI());
        final TokenRequest tokenRequest =
                new TokenRequest(oidcCtx.getoIDCProviderMetadata().getTokenEndpointURI(), clientAuth, codeGrant);
        final OIDCTokenResponse oidcTokenResponse;
        try {
            final TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
            // TokenResponse can only be TokenErrorResponse or OIDCTokenResponse
            if (tokenResponse instanceof OIDCTokenResponse) {
                oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
                if (!oidcTokenResponse.indicatesSuccess()) {
                    log.warn("{} Token response does not indicate success", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                    log.trace("Leaving");
                    return;
                } else {
                    oidcCtx.setOidcTokenResponse(oidcTokenResponse);
                    log.debug("Storing oidc token response to context: {}",
                            oidcTokenResponse.toJSONObject().toJSONString());
                }
            } else {
                final TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                log.warn("{} Error in getting token, response error is {}", getLogPrefix(),
                        errorResponse.getErrorObject());
                // should map error object OAuth2 Error types to new or existing event ids.
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }

        } catch (SerializeException | IOException | ParseException e) {
            log.error("{} token response failed", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        log.trace("Leaving");
    }
}
