
package net.shibboleth.idp.authn.oidc.impl;

import java.text.ParseException;
import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.claims.ACR;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * An action that verifies ACR of ID Token.
 * 
 * @event {@link net.shibboleth.idp.authn.AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class ValidateIDTokenACR extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateIDTokenACR.class);

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

        // Check acr
        // If the acr Claim was requested, the Client SHOULD check that the
        // asserted Claim Value is appropriate. The meaning and processing
        // of acr Claim Values is out of scope for this specification.
        final List<ACR> acrs = oidcCtx.getAcrs();
        if (acrs != null && acrs.size() > 0) {
            if (log.isTraceEnabled()) {
                for (int i = 0; i < acrs.size(); i++) {
                    log.trace("{} ACR index {} is {}", getLogPrefix(), i, acrs.get(i));
                }
            }
            final String acr;
            try {
                acr = oidcCtx.getIDToken().getJWTClaimsSet().getStringClaim("acr");
            } catch (ParseException e) {
                log.error("{} Error parsing id token", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
            if (StringSupport.trimOrNull(acr) == null) {
                log.error("{} acr requested but not received", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
            if (!acrs.contains(new ACR(acr))) {
                log.error("{} acr received does not match requested:" + acr, getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
        }
        log.trace("Leaving");
        return;
    }
}
