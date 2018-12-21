
package net.shibboleth.idp.authn.oidc.impl;

import java.text.ParseException;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.SocialUserOpenIdConnectContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that verifies Audience of ID Token.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 */
@SuppressWarnings("rawtypes")
public class ValidateOIDCIDTokenAudience extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCIDTokenAudience.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final SocialUserOpenIdConnectContext suCtx =
                authenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class);
        if (suCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (suCtx.getIDToken() == null) {
            log.error("{} Not able to find id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        // The Client MUST validate that the aud (audience) Claim contains
        // its client_id value registered at the Issuer identified by the
        // iss (issuer) Claim as an audience. The aud (audience) Claim MAY
        // contain an array with more than one element. The ID Token MUST be
        // rejected if the ID Token does not list the Client as a valid
        // audience, or if it contains additional audiences not trusted by
        // the Client.
        try {
            if (!suCtx.getIDToken().getJWTClaimsSet().getAudience().contains(suCtx.getClientID().getValue())) {
                log.error("{} client is not the intended audience", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
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
