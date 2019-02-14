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
 * An action that verifies the Authentication Context Class Reference (ACR) values contained within the 
 * id_token matches those requested.
 * 
 * <p>ACR claims are optional</p>
 * 
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @event {@link net.shibboleth.idp.authn.AuthnEventIds#NO_CREDENTIALS}
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * 
 * @since 4.0.0
 */
//TODO P.S should some of these functions be delegated to Nimbus IDTokenValidator? 
public class ValidateIDTokenACR extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateIDTokenACR.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        

        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Unable to find OIDC context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            
            return;
        }

        
        final List<ACR> acrs = oidcCtx.getAcrs();
        if (acrs != null && !acrs.isEmpty()) {
            if (log.isTraceEnabled()) {
                for (int i = 0; i < acrs.size(); i++) {
                    log.trace("{} ACR index {} is {}", getLogPrefix(), i, acrs.get(i));
                }
            }
            final String acr;
            try {
                //TODO P.S. this could be null.
                acr = oidcCtx.getIDToken().getJWTClaimsSet().getStringClaim("acr");
            } catch (final ParseException e) {
                log.error("{} Error parsing id token", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                
                return;
            }
            if (StringSupport.trimOrNull(acr) == null) {
                log.error("{} acr requested but not received", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                
                return;
            }
            if (!acrs.contains(new ACR(acr))) {
                log.error("{} acr received does not match requested:" + acr, getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                
                return;
            }
        }
        
        return;
    }
}
