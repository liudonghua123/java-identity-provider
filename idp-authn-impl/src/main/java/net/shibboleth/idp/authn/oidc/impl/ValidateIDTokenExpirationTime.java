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
 * An action that verifies the expiration time (exp) of an id_token. If the expiration time has past
 * the id_token must not be accepted.
 * 
 * <p>Some clock skew could be specified, but is not in this implementation</p>
 * 
 * <p>Expiration time of the id_token is required. If not present, AuthnEventIds#NO_CREDENTIALS is returned</p>
 * 
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @pre <pre>OpenIdConnectContext.getOidcTokenResponse() != null</pre>
 * 
 * @since 4.0.0
 */
public class ValidateIDTokenExpirationTime extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateIDTokenExpirationTime.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        

        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Unable to find oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }

        // The current time MUST be before the time represented by the expiration time of the token
        final Date currentDate = new Date();
        try {
            final Date expDate = oidcCtx.getIDToken().getJWTClaimsSet().getExpirationTime();
            if (currentDate.after(expDate)) {
                log.error("{} Current date {} is past exp date {}", getLogPrefix(), currentDate, expDate);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                
                return;
            }
        } catch (final java.text.ParseException | NullPointerException e) {
            log.error("{} Error parsing id token", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }        
        return;
    }

}
