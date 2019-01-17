/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.authn.oidc.impl;

import java.util.Date;

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
 * An action that verifies Expiration Time of ID Token.
 * 
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre
 * 
 *      <pre>
 *      AuthenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class, false) != null
 *      </pre>
 * 
 *      AND
 * 
 *      <pre>
 *      SocialUserOpenIdConnectContext.getOidcTokenResponse() != null
 *      </pre>
 */
@SuppressWarnings("rawtypes")
// TODO: Add preconditions to doc (suCtx.getOidcTokenResponse() etc)
public class ValidateIDTokenExpirationTime extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateIDTokenExpirationTime.class);

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

        // Check time
        // The current time MUST be before the time represented by the exp
        Date currentDate = new Date();
        try {
            Date expDate = oidcCtx.getIDToken().getJWTClaimsSet().getExpirationTime();
            if (currentDate.after(expDate)) {
                log.error("{} Current date {} is past exp date {}", getLogPrefix(), currentDate, expDate);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
        } catch (java.text.ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.trace("Leaving");
        return;
    }

}
