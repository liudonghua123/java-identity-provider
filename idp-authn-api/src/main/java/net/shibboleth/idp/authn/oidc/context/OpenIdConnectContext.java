/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.shibboleth.idp.authn.oidc.context;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.attribute.IdPAttribute;

import org.opensaml.messaging.context.BaseContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * This class is used to store oidc information produced in authentication for webflow to process later.
 */
public class OpenIdConnectContext extends BaseContext {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OpenIdConnectContext.class);

    /** Client Id. */
    @Nonnull
    private ClientID clientID;

    /** Client Secret. */
    @Nonnull
    private Secret clientSecret;

    /** Scope. */
    @Nonnull
    private Scope scope;

    /** OIDC Prompt. */
    private Prompt prompt;

    /** OIDC Authentication Class Reference values. */
    private List<ACR> acrs;

    /** OIDC Display. */
    private Display display;

    /** OIDC provider metadata. */
    private OIDCProviderMetadata oIDCProviderMetadata;

    /** oidc authentication request. */
    private URI authenticationRequestURI;

    /** oidc authentication response URI. */
    private URI authenticationResponseURI;

    /** oidc authentication success response. */
    private AuthenticationSuccessResponse authSuccessResponse;

    /** oidc token response. */
    private OIDCTokenResponse oidcTknResponse;

    /** State parameter. */
    private State state;

    /** Nonce parameter. */
    private Nonce nonce;

    /** Redirect URI. */
    private URI redirectURI;

    /** ID Token. */
    private JWT idToken;

    /** Resolved attributes. */
    private Map<String, IdPAttribute> resolvedIdPAttributes;

    /**
     * Get the resolved attributes.
     * 
     * @return resolved attributes, may be null.
     */
    public Map<String, IdPAttribute> getResolvedIdPAttributes() {
        return resolvedIdPAttributes;
    }

    /**
     * Set resolved attributes to context to help form requested objects.
     * 
     * @param idPAttributes resolved attributes
     */
    public void setResolvedIdPAttributes(Map<String, IdPAttribute> idPAttributes) {
        this.resolvedIdPAttributes = idPAttributes;
    }

    /**
     * Get the id token received from op.
     * 
     * @return id token or null if not set.
     */
    public JWT getIDToken() {
        return idToken;
    }

    /**
     * Set the id token received from op.
     * 
     * @param token from op.
     */
    public void setIDToken(JWT token) {
        this.idToken = token;
    }

    /**
     * Get the redirect uri of the client.
     * 
     * @return redirect uri
     */
    public URI getRedirectURI() {
        return redirectURI;
    }

    /**
     * Get the redirect uri of the client.
     * 
     * @param uri of the client.
     */
    public void setRedirectURI(URI uri) {
        this.redirectURI = uri;
    }

    /**
     * Getter for Oauth2 client id.
     * 
     * @return client id.
     */
    public ClientID getClientID() {
        return clientID;
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param id Oauth2 Client ID
     */
    public void setClientID(ClientID id) {
        this.clientID = id;
    }

    /**
     * Set the client secret.
     * 
     * @param secret of the client
     */
    public void setClientSecret(Secret secret) {
        this.clientSecret = secret;
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
    public void setScope(Scope scp) {
        this.scope = scp;
    }

    /**
     * Get the value for prompt used for forming authentication request.
     * 
     * @return prompt
     */
    public Prompt getPrompt() {
        return prompt;
    }

    /**
     * Get the value for prompt used for forming authentication request.
     * 
     * @param prmpt used for for forming authentication request
     */
    public void setPrompt(Prompt prmpt) {
        this.prompt = prmpt;
    }

    /**
     * Get the values for acr used for forming authentication request.
     * 
     * @return acrs
     */
    public List<ACR> getAcrs() {
        return acrs;
    }

    /**
     * Set the values for acr used for forming authentication request.
     * 
     * @param acrList values used for forming authentication request
     */
    public void setAcrs(List<ACR> acrList) {
        this.acrs = acrList;
    }

    /**
     * Get the display value used for forming authentication request.
     * 
     * @return display
     */
    public Display getDisplay() {
        return display;
    }

    /**
     * Set the display value used for forming authentication request.
     * 
     * @param dspl value for forming authentication request.
     */
    public void setDisplay(Display dspl) {
        this.display = dspl;
    }

    /**
     * Get op metadata.
     * 
     * @return op metadata
     */
    public OIDCProviderMetadata getoIDCProviderMetadata() {
        return oIDCProviderMetadata;
    }

    /**
     * Set op metatadata.
     * 
     * @param oIDCPrvdrMtdt op metadata.
     */
    public void setoIDCProviderMetadata(OIDCProviderMetadata oIDCPrvdrMtdt) {
        this.oIDCProviderMetadata = oIDCPrvdrMtdt;
    }

    /**
     * Returns the oidc authentication request URI to be used for authentication.
     * 
     * @return request URI for authentication
     */
    public URI getAuthenticationRequestURI() {
        log.trace("Entering & Leaving");
        return authenticationRequestURI;
    }

    /**
     * Set the oidc provider request for authentication.
     * 
     * @param request to be used for authentication
     */
    public void setAuthenticationRequestURI(URI request) {
        log.trace("Entering");
        log.debug("Setting auth request redirect to " + request.toString());
        this.authenticationRequestURI = request;
        log.trace("Leaving");
    }

    /**
     * Returns token response or null.
     * 
     * @return token response
     */
    public OIDCTokenResponse getOidcTokenResponse() {
        log.trace("Entering & Leaving");
        return oidcTknResponse;
    }

    /**
     * Sets token response.
     * 
     * @param oidcTokenResponse response from provider
     */
    public void setOidcTokenResponse(OIDCTokenResponse oidcTokenResponse) {
        log.trace("Entering");
        this.oidcTknResponse = oidcTokenResponse;
        if (oidcTokenResponse != null && oidcTokenResponse.getOIDCTokens() != null) {
            this.idToken = oidcTokenResponse.getOIDCTokens().getIDToken();
        }
        log.trace("Leaving");
    }

    /**
     * Getter for State parameter.
     * 
     * @return state parameter
     */
    public State getState() {
        return state;
    }

    /**
     * Setter for State parameter.
     * 
     * @param stateParam parameter
     */
    public void setState(State stateParam) {
        this.state = stateParam;
    }

    /**
     * Getter for Nonce parameter.
     * 
     * @return nonce parameter.
     */
    public Nonce getNonce() {
        return nonce;
    }

    /**
     * Setter for Nonce parameter.
     * 
     * @param newNonce nonce parameter
     */
    public void setNonce(Nonce newNonce) {
        this.nonce = newNonce;
    }

    /**
     * Returns authentication success response or null.
     * 
     * @return authentication success response.
     */
    public AuthenticationSuccessResponse getAuthenticationSuccessResponse() {
        log.trace("Entering & Leaving");
        return authSuccessResponse;
    }

    /**
     * Sets authentication success response.
     * 
     * @param authenticationSuccessResponse response from ther provider
     */
    public void setAuthenticationSuccessResponse(AuthenticationSuccessResponse authenticationSuccessResponse) {
        log.trace("Entering");
        this.authSuccessResponse = authenticationSuccessResponse;
        log.trace("Leaving");
    }

    /**
     * Returns authentication response URI or null.
     * 
     * @return authentication response URI
     */
    public URI getAuthenticationResponseURI() {
        log.trace("Entering & Leaving");
        return authenticationResponseURI;
    }

    /**
     * Parses authentication response URI from request.
     * 
     * @param authenticationResponseHttpRequest request
     * 
     * @throws URISyntaxException if request has malformed URL and/or query parameters
     */
    public void setAuthenticationResponseURI(HttpServletRequest authenticationResponseHttpRequest)
            throws URISyntaxException {
        log.trace("Entering");
        String temp = authenticationResponseHttpRequest.getRequestURL() + "?"
                + authenticationResponseHttpRequest.getQueryString();
        this.authenticationResponseURI = new URI(temp);
        log.trace("Leaving");

    }

    /**
     * Get client secret.
     * 
     * @return client secret.
     */
    public Secret getClientSecret() {
        return clientSecret;
    }

}
