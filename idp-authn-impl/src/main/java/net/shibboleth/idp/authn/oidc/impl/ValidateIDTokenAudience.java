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

import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

/**
 * An action that verifies the Audience (aud) claim in the id_token contains the client_id of this
 * client (as registered at the issuer).  See section 3.1.3.7 of OpenID Connect core 1.0.
 * 
 * <p>If one of the list of audiences is untrusted, the token should be rejected - which is 
 * Currently NOT tested</p>
 * 
 * 
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @pre <pre>OpenIDConnectContext.getIDToken() != null</pre>
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID} 
 * @event {@link net.shibboleth.idp.authn.AuthnEventIds#NO_CREDENTIALS}
 * 
 * @since 4.0.0
 */
//TODO P.S should some of these functions be delegated to Nimbus IDTokenValidator?
public class ValidateIDTokenAudience extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateIDTokenAudience.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        

        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Not able to find oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);           
            return;
        }
        if (oidcCtx.getIDToken() == null) {
            log.error("{} Not able to find id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }

        try {
            //TODO P.S. getClientID could be null, although not after SetOIDCInformation has run.
            if (!oidcCtx.getIDToken().getJWTClaimsSet().getAudience().contains(oidcCtx.getClientID().getValue())) {
                log.error("{} client is not the intended audience", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                
                return;
            }
        } catch (final ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }       
        return;
    }

}
