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

import java.io.IOException;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

/**
 * An action that exchanges the OAuth 2.0 authorization code inside the {@link OpenIDConnectContext} for
 * an id_token from the OpenID Connect Provider's Token Endpoint. The ID Token is placed inside the 
 * {@link OpenIDConnectContext}.
 * 
 * 
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @post If getIDToken() !=null the method returns immediately. Otherwise, if the token endpoint returns an 
 * {@link OIDCTokenResponse} whose indicatesSuccess()==true, the token is attached to the {@link OpenIDConnectContext}.
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * 
 * @since 4.0.0
 */
public class GetOIDCTokenResponse extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(GetOIDCTokenResponse.class);

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
        if (oidcCtx.getIDToken() != null) {
            log.debug("id_token already exists, nothing to fetch from token endpoint");
            
            return;
        }
        final AuthenticationSuccessResponse response = oidcCtx.getAuthenticationSuccessResponse();
        
        if (response == null) {
            log.info("{} Authentication success response not found in OpenIDConnectContext", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
           
            return;
        }
        final AuthorizationCode code = response.getAuthorizationCode();
        //TODO P.S. code could be null, should not be.
        final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, oidcCtx.getRedirectURI());
        //TODO P.S. neither should be null, both could be (although not after SetOIDCInformation initilises the context)
        final ClientAuthentication clientAuth = new ClientSecretBasic(oidcCtx.getClientID(), oidcCtx.getClientSecret());
        
        log.trace("{} Using the following OIDC token endpoint URI: {}", getLogPrefix(),
                oidcCtx.getoIDCProviderMetadata().getTokenEndpointURI());
        
        final TokenRequest tokenRequest =
                new TokenRequest(oidcCtx.getoIDCProviderMetadata().getTokenEndpointURI(), clientAuth, codeGrant);
        final OIDCTokenResponse oidcTokenResponse;
        try {
            final TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
            // TokenResponse can only be TokenErrorResponse or OIDCTokenResponse
            if (tokenResponse instanceof OIDCTokenResponse) {
                
                oidcTokenResponse = (OIDCTokenResponse) tokenResponse;                
                oidcCtx.setOidcTokenResponse(oidcTokenResponse);
                
            } else {
                final TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                log.warn("{} Error in retrieving id_token, response error is {}", getLogPrefix(),
                        errorResponse.getErrorObject());
                // should map error object OAuth2 Error types to new or existing event ids.
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }

        } catch (final SerializeException | IOException | ParseException e) {
            log.error("{} token response failed", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
           
            return;
        }

       
    }
}
