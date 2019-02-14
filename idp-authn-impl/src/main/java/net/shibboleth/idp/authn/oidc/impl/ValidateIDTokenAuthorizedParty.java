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
 * An action that verifies the Authorized Party (azp) of an id_token. That is, the party to which
 * the id_token was issued, or the presenter of the id_token. As the IdP will always be responsible
 * for presenting the id_token, this value should always be the same client_id as the sole audience (aud).
 * As such, azp is not strictly required, but is checked if present. 
 * 
 * <p>The authorized party is one or more case sensitive Strings or URIs.</p>
 * 
 * <p>See section 3.1.3.7 of the OpenID Connect core 1.0</p>
 * 
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @pre <pre>OpenIDConnectContext.getIDToken() != null</pre>
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * 
 * @since 4.0.0
 */
//Issues of semantics exist here e.g. https://bitbucket.org/openid/connect/issues/973/
//TODO the code does not match the spec?
public class ValidateIDTokenAuthorizedParty extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateIDTokenAuthorizedParty.class);

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

        try {
            if (oidcCtx.getIDToken().getJWTClaimsSet().getAudience().size() > 1) {
                final String azp = oidcCtx.getIDToken().getJWTClaimsSet().getStringClaim("azp");
                if (!oidcCtx.getClientID().getValue().equals(azp)) {
                    log.error("{} multiple audiences, client is not the azp", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                   
                    return;
                }
            }
        } catch (final ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }       
        return;
    }

}
