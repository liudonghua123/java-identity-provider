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

package net.shibboleth.idp.authn.oidc.context;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.utilities.java.support.annotation.constraint.Live;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.BaseContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * This class is used to store oidc information produced in authentication for webflow to process later.
 */
public class OpenIDConnectContext extends BaseContext {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(OpenIDConnectContext.class);

    /** Client Id. */
    @Nullable private ClientID clientID;

    /** Client Secret. */
    @Nullable private Secret clientSecret;

    /** Scope. */
    @Nullable private Scope scope;

    /** OIDC Prompt. */
    @Nullable private Prompt prompt;

    /** OIDC Authentication Class Reference values. Can be null if not required.*/
    @Nullable @NonnullElements private List<ACR> acrs;

    /** OIDC Display. */
    @Nullable private Display display;

    /** OIDC provider metadata. */
    @Nullable private OIDCProviderMetadata oIDCProviderMetadata;

    /** oidc authentication request. */
    @Nullable private URI authenticationRequestURI;

    /** oidc authentication response URI. */
    @Nullable private URI authenticationResponseURI;

    /** oidc authentication success response. */
    @Nullable private AuthenticationSuccessResponse authSuccessResponse;

    /** oidc token response. */
    @Nullable private OIDCTokenResponse oidcTknResponse;

    /** State parameter. */
    @Nullable private State state;

    /** Nonce parameter. */
    @Nullable private Nonce nonce;

    /** Redirect URI. */
    @Nullable private URI redirectURI;

    /** ID Token. */
    @Nullable private JWT idToken;

    /** Resolved attributes. */
    //TODO Resolved Attributes never get added to the Context.
    @Nullable private Map<String, IdPAttribute> resolvedIdPAttributes;
    

    /**
     * Get the resolved attributes.
     * 
     * @return resolved attributes, may be null.
     */
    @Nullable @Live public Map<String, IdPAttribute> getResolvedIdPAttributes() {
        return resolvedIdPAttributes;
    }

    /**
     * Set resolved attributes to context to help form requested objects.
     * 
     * @param idPAttributes resolved attributes
     */
    public void setResolvedIdPAttributes(@Nullable final Map<String, IdPAttribute> idPAttributes) {
        resolvedIdPAttributes = idPAttributes;
    }

    /**
     * Get the id token received from op.
     * 
     * @return id token or null if not set.
     */
    @Nullable public JWT getIDToken() {
        return idToken;
    }

    /**
     * Set the id token received from op.
     * 
     * @param token from op.
     */
    public void setIDToken(@Nullable final JWT token) {
        idToken = token;
    }

    /**
     * Get the redirect uri of the client.
     * 
     * @return redirect uri
     */
    @Nullable public URI getRedirectURI() {
        return redirectURI;
    }

    /**
     * Set the redirect URI of the client. Redirect URI must not be 
     * <code>null</code>, and is required for authorisation code flows 
     * (see OpenID Connect Core 1.0 section 3.1.2.1). 
     * 
     * @param uri of the client.
     */
    public void setRedirectURI(@Nonnull final URI uri) {
        redirectURI = Constraint.isNotNull(uri, "Redirect URI cannot be null");
    }

    /**
     * Getter for Oauth2 client id.
     * 
     * @return client id.
     */
    @Nullable public ClientID getClientID() {
        return clientID;
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param id Oauth2 Client ID
     */
    public void setClientID(@Nonnull final ClientID id) {
        clientID = Constraint.isNotNull(id, "Client ID cannot be null");
    }

    /**
     * Set the client secret.
     * 
     * @param secret of the client
     */
    public void setClientSecret(@Nonnull final Secret secret) {
        clientSecret = Constraint.isNotNull(secret, "Client secret cannot be null");
    }
    
    /**
     * Get client secret.
     * 
     * @return client secret.
     */
    @Nullable public Secret getClientSecret() {
        return clientSecret;
    }

    /**
     * Get the scope used for authentication request.
     * 
     * @return scope
     */
    public Scope getScope() {
        return scope;
    }

    /**
     * Set the scope used for forming authentication request.
     * 
     * @param scp scope of the request
     */
    public void setScope(@Nonnull final Scope scp) {
        scope = Constraint.isNotNull(scp, "Scope cannot be null");
    }

    /**
     * Get the value for prompt used for forming authentication request.
     * 
     * @return prompt
     */
    @Nullable public Prompt getPrompt() {
        return prompt;
    }

    /**
     * Set the value for prompt used for forming authentication request.
     * 
     * @param prmpt used for for forming authentication request
     */
    public void setPrompt(@Nullable final Prompt prmpt) {
        prompt = prmpt;
    }

    /**
     * Get the values for acr used for forming authentication request. 
     * <code>null</code> if not set.
     * 
     * @return acrs
     */
    @Nullable @NonnullElements @Unmodifiable @NotLive public List<ACR> getAcrs() {
       return acrs;
    }

    /**
     * Set the values for acr used for forming authentication request. Allows for a null {@link List} 
     * if no ACRs are defined in order to maintain direct compatibility with the 
     * Nimbus {@link AuthenticationRequest} builder.
     * 
     * @param acrList values used for forming authentication request
     */
    public void setAcrs(@Nullable @NonnullElements final List<ACR> acrList) {
        if (acrList!=null) {
            ImmutableList.copyOf(Collections2.filter(acrList, Predicates.notNull()));
        } else {
            acrs = null;           
        }

    }

    /**
     * Get the display value used for forming authentication request.
     * 
     * @return display
     */
    @Nullable public Display getDisplay() {
        return display;
    }

    /**
     * Set the display value used for forming authentication request.
     * 
     * @param dspl value for forming authentication request.
     */
    public void setDisplay(@Nullable final Display dspl) {
        display = dspl;
    }

    /**
     * Get op metadata.
     * 
     * @return op metadata
     */
    @Nullable public OIDCProviderMetadata getoIDCProviderMetadata() {
        return oIDCProviderMetadata;
    }

    /**
     * Set op metatadata.
     * 
     * @param oIDCPrvdrMtdt op metadata.
     */
    public void setoIDCProviderMetadata(@Nonnull final OIDCProviderMetadata oIDCPrvdrMtdt) {
        oIDCProviderMetadata = Constraint.isNotNull(oIDCPrvdrMtdt, "OpenID Connect metadata location cannot be null ");
    }

    /**
     * Returns the oidc authentication request URI to be used for authentication.
     * 
     * @return request URI for authentication
     */
    @Nullable public URI getAuthenticationRequestURI() {
        return authenticationRequestURI;
    }

    /**
     * Set the oidc provider request for authentication.
     * 
     * @param request to be used for authentication
     */
    public void setAuthenticationRequestURI(@Nonnull final URI request) {
        authenticationRequestURI = Constraint.isNotNull(request, 
                "Authentication Request URI request can not be null");      

    }

    /**
     * Returns token response or null.
     * 
     * @return token response
     */
    @Nullable public OIDCTokenResponse getOidcTokenResponse() {
        return oidcTknResponse;
    }

    /**
     * Sets token response.
     * 
     * @param oidcTokenResponse response from provider
     */
    public void setOidcTokenResponse(@Nullable final OIDCTokenResponse oidcTokenResponse) {
        oidcTknResponse = oidcTokenResponse;
        if (oidcTokenResponse != null && oidcTokenResponse.getOIDCTokens() != null) {
            idToken = oidcTokenResponse.getOIDCTokens().getIDToken();
        }

    }

    /**
     * Getter for State parameter.
     * 
     * @return state parameter
     */
    @Nullable public State getState() {
        return state;
    }

    /**
     * Setter for State parameter.
     * 
     * @param stateParam parameter
     */
    public void setState(@Nullable final State stateParam) {
        state = stateParam;
    }

    /**
     * Getter for Nonce parameter.
     * 
     * @return nonce parameter.
     */
    @Nullable public Nonce getNonce() {
        return nonce;
    }

    /**
     * Setter for Nonce parameter.
     * 
     * @param newNonce nonce parameter
     */
    public void setNonce(@Nullable final Nonce newNonce) {
        nonce = newNonce;
    }

    /**
     * Returns authentication success response or null.
     * 
     * @return authentication success response.
     */
    @Nullable public AuthenticationSuccessResponse getAuthenticationSuccessResponse() {
        return authSuccessResponse;
    }

    /**
     * Sets authentication success response.
     * 
     * @param authenticationSuccessResponse response from ther provider
     */
    public void setAuthenticationSuccessResponse(
            @Nonnull final AuthenticationSuccessResponse authenticationSuccessResponse) {
        authSuccessResponse = Constraint.isNotNull(authenticationSuccessResponse, 
                "AuthenticationSuccessResponse can not be null");      

    }

    /**
     * Returns authentication response URI or null.
     * 
     * @return authentication response URI
     */
    @Nullable public URI getAuthenticationResponseURI() {
        return authenticationResponseURI;
    }

    /**
     * Parses authentication response URI from request.
     * 
     * @param authenticationResponseHttpRequest request
     * 
     * @throws URISyntaxException if request has malformed URL and/or query parameters
     */
    public void setAuthenticationResponseURI(@Nonnull final HttpServletRequest authenticationResponseHttpRequest)
            throws URISyntaxException {

        //This will NPE anyway if null.
        Constraint.isNotNull(authenticationResponseHttpRequest, "Authentication response http request can not be null");
        
        final String temp = authenticationResponseHttpRequest.getRequestURL() + "?"
                + authenticationResponseHttpRequest.getQueryString();
        authenticationResponseURI = new URI(temp);

    }

  

}
