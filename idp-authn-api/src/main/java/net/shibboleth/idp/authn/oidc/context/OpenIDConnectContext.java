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
import net.shibboleth.idp.authn.context.AuthenticationContext;
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
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


/**
 * Context that carries OpenID Connect client and provider metadata used during authentication of a subject from
 * an OpenID Connect Provider.
 * 
 * <p>Any OPTIONAL parameters of an ODIC authentication request are allowably <code>null</code> - even Lists.
 * For a list of OPTIONAL authn parameters, see OpenID Connect Core 1.0 section 3.1.2.1</p>
 *
 * 
 * @parent {@link AuthenticationContext}
 * @added After the RelyingPartyUIContext has been added, before external redirect to the OpenID Connect servlet. 
 * 
 * @since 4.0.0
 */
public class OpenIDConnectContext extends BaseContext {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(OpenIDConnectContext.class);

    /** Client Id. */
    @Nullable private ClientID clientID;

    /** Client Secret. */
    @Nullable private Secret clientSecret;

    /** Scope. Must contain an openid scope.*/
    @Nullable private Scope scope;

    /**
     *  OIDC Prompt. Specifies whether the Authorization Server prompts
     *  the End-User for re-authentication and consent.
     */
    @Nullable private Prompt prompt;

    /** OIDC Authentication Class Reference values.*/
    @Nullable @NonnullElements private List<ACR> acrs;

    /**
     *  OIDC Display. Value that specifies how the Authorization Server
     *  displays the authentication and consent user interface pages to the End-User. 
     */
    @Nullable private Display display;

    /** OIDC provider metadata. */
    @Nullable private OIDCProviderMetadata oIDCProviderMetadata;

    /** OIDC authentication request URI. */
    @Nullable private URI authenticationRequestURI;

    /** OIDC authentication response URI. */
    @Nullable private URI authenticationResponseURI;

    /** OIDC authentication success response. */
    @Nullable private AuthenticationSuccessResponse authSuccessResponse;

    /** OIDC token response. */
    @Nullable private OIDCTokenResponse oidcTknResponse;

    /** 
     * State parameter. Opaque value used to maintain state between the request 
     * and the callback. Typically for CSRF protection. 
     */
    @Nullable private State state;

    /** 
     * Nonce parameter. String value used to associate a Client session with an 
     * ID Token, and to mitigate replay attacks.
     */
    @Nullable private Nonce nonce;

    /** Redirect URI to which the response will be sent. */
    @Nullable private URI redirectURI;

    /** ID Token from the token endpoint response. */
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
     * Get the id token received from OpenID Connect Provider.
     * 
     * @return id token or <code>null</code> if not set.
     */
    @Nullable public JWT getIDToken() {
        return idToken;
    }

    /**
     * Set the id token received from OpenID Connect Provider.
     * 
     * @param token from the OpenID Connect Provider.
     */
    public void setIDToken(@Nullable final JWT token) {
        idToken = token;
    }

    /**
     * Get the redirect URI of the client.
     * 
     * @return redirect uri
     */
    @Nullable public URI getRedirectURI() {
        return redirectURI;
    }

    /**
     * Set the redirect URI of the client. The redirect URI is required for authorisation code flows. 
     * 
     * @param uri of the client, must not be <code>null</code>.
     */
    public void setRedirectURI(@Nonnull final URI uri) {
        redirectURI = Constraint.isNotNull(uri, "Redirect URI cannot be null");
    }

    /**
     * Get the OAuth2 client id.
     * 
     * @return client id.
     */
    @Nullable public ClientID getClientID() {
        return clientID;
    }

    /**
     * Set the Oauth2 client id. The client id can not be <code>null</code>.
     * 
     * @param id Oauth2 Client ID, must not be <code>null</code>.
     */
    public void setClientID(@Nonnull final ClientID id) {
        clientID = Constraint.isNotNull(id, "Client ID cannot be null");
    }

    /**
     * Set the client secret.
     * 
     * @param secret of the client, must not be <code>null</code>.
     */
    public void setClientSecret(@Nonnull final Secret secret) {
        clientSecret = Constraint.isNotNull(secret, "Client secret cannot be null");
    }
    
    /**
     * Get the client secret.
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
     * Set the scope used for forming an authentication request.
     * 
     * @param scp scope of the request, must not be <code>null</code>
     */
    public void setScope(@Nonnull final Scope scp) {
        scope = Constraint.isNotNull(scp, "Scope cannot be null");
    }

    /**
     * Get the value for prompt used for forming an authentication request.
     * 
     * @return prompt
     */
    @Nullable public Prompt getPrompt() {
        return prompt;
    }

    /**
     * Set the value for prompt used for forming an authentication request.
     * 
     * @param prmpt used for forming an authentication request
     */
    public void setPrompt(@Nullable final Prompt prmpt) {
        prompt = prmpt;
    }

    /**
     * Get the values for acr used for forming authentication request. 
     * Allowably a <code>null</code> {@link List} if not set.
     * 
     * @return acrs or <code>null</code> if not set.
     */
    @Nullable @NonnullElements @Unmodifiable @NotLive public List<ACR> getAcrs() {
       return acrs;
    }

    /**
     * Set the values for acr used for forming authentication request. Sets a 
     * <code>null</code> {@link List} if no ACRs are defined.
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
     * Get OpenID Connect Provider metadata.
     * 
     * @return OpenID Connect Provider metadata
     */
    @Nullable public OIDCProviderMetadata getoIDCProviderMetadata() {
        return oIDCProviderMetadata;
    }

    /**
     * Set OpenID Connect Provider metatadata.
     * 
     * @param oIDCPrvdrMtdt OpenID Connect Provider metadata, must not be <code>null</code>.
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
     * Set the oidc provider request URI for authentication.
     * 
     * @param request to be used for authentication, must not be <code>null</code>.
     */
    public void setAuthenticationRequestURI(@Nonnull final URI request) {
        authenticationRequestURI = Constraint.isNotNull(request, 
                "Authentication Request URI request can not be null");      

    }

    /**
     * Returns the OIDC token response or null.
     * 
     * @return token response
     */
    @Nullable public OIDCTokenResponse getOidcTokenResponse() {
        return oidcTknResponse;
    }

    /**
     * Sets both the token response and the <code>idToken</code> from the
     * token response if it is not <code>null</code>.
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
     * Returns the authentication success response or null.
     * 
     * @return authentication success response.
     */
    @Nullable public AuthenticationSuccessResponse getAuthenticationSuccessResponse() {
        return authSuccessResponse;
    }

    /**
     * Sets the authentication success response.
     * 
     * @param authenticationSuccessResponse response from the OpenIDConenct Provider
     */
    public void setAuthenticationSuccessResponse(
            @Nonnull final AuthenticationSuccessResponse authenticationSuccessResponse) {
        authSuccessResponse = Constraint.isNotNull(authenticationSuccessResponse, 
                "AuthenticationSuccessResponse can not be null");      

    }

    /**
     * Returns the authentication response URI or null.
     * 
     * @return authentication response URI
     */
    @Nullable public URI getAuthenticationResponseURI() {
        return authenticationResponseURI;
    }

    /**
     * Parses the authentication response URI from the authenticationResponseHttpRequest.
     * 
     * @param authenticationResponseHttpRequest request
     * 
     * @throws URISyntaxException if request has malformed URL and/or query parameters
     */
    public void setAuthenticationResponseURI(@Nonnull final HttpServletRequest authenticationResponseHttpRequest)
            throws URISyntaxException {

        Constraint.isNotNull(authenticationResponseHttpRequest, "Authentication response http request can not be null");
        
        final String temp = authenticationResponseHttpRequest.getRequestURL() + "?"
                + authenticationResponseHttpRequest.getQueryString();
        authenticationResponseURI = new URI(temp);

    }

  

}
