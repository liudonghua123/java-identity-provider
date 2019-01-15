
package net.shibboleth.idp.authn.oidc.impl;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIdConnectContext;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

/**
 * An action that creates a {@link OpenIdConnectContext}, and attaches it to the
 * {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class ValidateOIDCAuthenticationResponse extends AbstractExtractionAction {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCAuthenticationResponse.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final OpenIdConnectContext suCtx =
                authenticationContext.getSubcontext(OpenIdConnectContext.class);
        if (suCtx == null) {
            log.info("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        if (suCtx.getAuthenticationResponseURI() == null) {
            log.info("{} response uri not set", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.debug("Validating response {}", suCtx.getAuthenticationResponseURI().toString());
        AuthenticationResponse response = null;
        try {
            response = AuthenticationResponseParser.parse(suCtx.getAuthenticationResponseURI());
        } catch (ParseException e) {
            log.info("{} response parsing failed", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (!response.indicatesSuccess()) {
            log.trace("Leaving");
            AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) response;
            String error = errorResponse.getErrorObject().getCode();
            String errorDescription = errorResponse.getErrorObject().getDescription();
            if (StringSupport.trimOrNull(errorDescription) != null) {
                error += " : " + errorDescription;
            }
            log.trace("Leaving");
            log.info("{} response indicated error: {}", getLogPrefix(), error);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;
        // implicit and hybrid flows return id token in response.
        suCtx.setIDToken(successResponse.getIDToken());
        State state = suCtx.getState();
        if (state == null || !state.equals(successResponse.getState())) {
            log.info("{} state mismatch:", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
        }

        suCtx.setAuthenticationSuccessResponse(successResponse);
        log.trace("Leaving");
        return;
    }

}
