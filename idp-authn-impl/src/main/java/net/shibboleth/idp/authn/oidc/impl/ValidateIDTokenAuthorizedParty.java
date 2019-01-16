
package net.shibboleth.idp.authn.oidc.impl;

import java.text.ParseException;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that verifies Authorized Party of ID Token.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class ValidateIDTokenAuthorizedParty extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateIDTokenAuthorizedParty.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");
        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        // If the ID Token contains multiple audiences, the Client SHOULD
        // verify that an azp Claim is present.
        // If an azp (authorized party) Claim is present, the Client SHOULD
        // verify that its client_id is the Claim Value.
        try {
            if (oidcCtx.getIDToken().getJWTClaimsSet().getAudience().size() > 1) {
                final String azp = oidcCtx.getIDToken().getJWTClaimsSet().getStringClaim("azp");
                if (!oidcCtx.getClientID().getValue().equals(azp)) {
                    log.error("{} multiple audiences, client is not the azp", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                    log.trace("Leaving");
                    return;
                }
            }
        } catch (ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.trace("Leaving");
        return;
    }

}
