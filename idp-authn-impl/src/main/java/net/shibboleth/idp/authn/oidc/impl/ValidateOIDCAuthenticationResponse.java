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

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
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
 * An action that extracts the id_token from the query parameters of a successful response from
 * an OpenID Connect provider. The id_token is attached to the {@link OpenIDConnectContext}.  
 *  
 * <p>Also checks the state returned by the provider matches that which was sent to the provider</p>
 * 
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @pre <pre>OpenIdConnectContext.getAuthenticationResponseURI() != null</pre>
 * @post If {@link AuthenticationResponse#indicatesSuccess()} == true, the extracted id_token
 * is extracted and placed into the existing {@link OpenIDConnectContext}.
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * 
 * @since 4.0.0
 */
public class ValidateOIDCAuthenticationResponse extends AbstractExtractionAction {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateOIDCAuthenticationResponse.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        

        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.info("{} Unable to find oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }

        if (oidcCtx.getAuthenticationResponseURI() == null) {
            log.info("{} Response URI not set", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        log.debug("Validating OIDC response {}", oidcCtx.getAuthenticationResponseURI().toString());
        AuthenticationResponse response = null;
        try {
            response = AuthenticationResponseParser.parse(oidcCtx.getAuthenticationResponseURI());
        } catch (final ParseException e) {
            log.info("{} Response parsing failed", getLogPrefix(),e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        if (!response.indicatesSuccess()) {
            
            final AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) response;
            String error = errorResponse.getErrorObject().getCode();
            final String errorDescription = errorResponse.getErrorObject().getDescription();
            if (StringSupport.trimOrNull(errorDescription) != null) {
                error += " : " + errorDescription;
            }
           
            log.info("{} response indicated error: {}", getLogPrefix(), error);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        final AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;
        // implicit and hybrid flows return id token in response.
        oidcCtx.setIDToken(successResponse.getIDToken());
        final State state = oidcCtx.getState();
        if (state == null || !state.equals(successResponse.getState())) {
            log.info("{} OIDC flow state mismatch:", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            
        }

        oidcCtx.setAuthenticationSuccessResponse(successResponse);
        
        return;
    }

}
