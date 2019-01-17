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
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.annotation.Nonnull;

import net.minidev.json.JSONObject;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.Prompt.Type;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jwt.SignedJWT;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that sets oidc information to {@link OpenIDConnectContext} and attaches it to
 * {@link AuthenticationContext}.
 */
@SuppressWarnings("rawtypes")
public class SetOIDCInformation extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SetOIDCInformation.class);

    /** Context to look attributes for. */
    @Nonnull
    private Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy;

    /** Redirect URI. */
    private URI redirectURI;

    /** Client Id. */
    @Nonnull
    private ClientID clientID;

    /** Client Secret. */
    @Nonnull
    private Secret clientSecret;

    /** Response type, default is code flow. */
    @Nonnull
    private ResponseType responseType = new ResponseType(ResponseType.Value.CODE);

    /** Scope. */
    @Nonnull
    private Scope scope = new Scope(OIDCScopeValue.OPENID);

    /** OIDC Prompt. */
    private Prompt prompt;

    /** OIDC Authentication Class Reference values. */
    private List<ACR> acrs;

    /** OIDC Display. */
    private Display display;

    /** Private key for signing request object. */
    private PrivateKey signPrvKey;

    /** Algorithm used for signing the request object. */
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

    /** key id for key used for signing the request object. */
    private String keyID = "id";

    /** Request object claims. */
    private Map<String, String> requestClaims;

    /** OIDC provider metadata. */
    private OIDCProviderMetadata oIDCProviderMetadata;

    /** Constructor. */
    public SetOIDCInformation() {
        log.trace("Entering");
        attributeContextLookupStrategy = Functions.compose(new ChildContextLookup<>(AttributeContext.class),
                new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));
        log.trace("Leaving");
        
    }

    /**
     * Set the private key used for signing request object.
     * 
     * @param key signing key
     */
    public void setPrivKey(PrivateKey key) {
        this.signPrvKey = key;
    }

    /**
     * Set the RSA algorithm used for signing. Default is RS256.
     * 
     * @param algorithm used for signing
     */
    public void setJwsAlgorithm(JWSAlgorithm algorithm) {
        this.jwsAlgorithm = algorithm;
    }

    /**
     * Set the key id of the key.
     * 
     * @param id for the key.
     */
    public void setKeyID(String id) {
        this.keyID = id;
    }

    /**
     * 
     * Request object is created only if this mapping is set. Key of the mapping is the name of the requested claim.
     * Value of requested claim is a) value of matching attribute if such is found, otherwise b) {"essential":true} if
     * mapped value is "essential", otherwise c) the mapped value. Mapped value may be null.
     * 
     * @param claims map of requested claims
     */
    public void setRequestClaims(Map<String, String> claims) {
        this.requestClaims = claims;
    }

    /**
     * Sets the response type. Default is code. *
     * 
     * @param type space-delimited list of one or more authorization response types.
     * @throws ParseException if response type cannot be parsed
     */
    public void setResponseType(String type) throws ParseException {
        log.trace("Entering & Leaving");
        this.responseType = ResponseType.parse(type);
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param oauth2ClientId Oauth2 Client ID
     */
    public void setClientID(String oauth2ClientID) {
        log.trace("Entering & Leaving");
        this.clientID = new ClientID(oauth2ClientID);
    }

    /**
     * Setter for Oauth2 Client secret.
     * 
     * @param oauth2ClientSecret Oauth2 Client Secret
     */
    public void setClientSecret(String oauth2ClientSecret) {
        log.trace("Entering & Leaving");
        this.clientSecret = new Secret(oauth2ClientSecret);
    }

    /**
     * Setter for OAuth2 redirect uri for provider to return to.
     * 
     * @param redirect OAuth2 redirect uri
     */

    public void setRedirectURI(URI redirect) {
        this.redirectURI = redirect;
    }

    /**
     * Setter for OpenId Provider Metadata location.
     * 
     * @param metadataLocation OpenId Provider Metadata location
     * @throws URISyntaxException if metadataLocation is not URI
     * @throws IOException if metadataLocation cannot be read
     * @throws ParseException if metadataLocation has wrong content
     */
    public void setProviderMetadataLocation(String metadataLocation)
            throws URISyntaxException, IOException, ParseException {
        log.trace("Entering");
        URI issuerURI = new URI(metadataLocation);
        URL providerConfigurationURL = issuerURI.resolve(".well-known/openid-configuration").toURL();
        InputStream stream = providerConfigurationURL.openStream();
        String providerInfo = null;
        try (java.util.Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        }
        oIDCProviderMetadata = OIDCProviderMetadata.parse(providerInfo);
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Scope values.
     * 
     * @param oidcScopes OpenId Scope values
     */
    public void setScope(List<String> oidcScopes) {
        log.trace("Entering");
        for (String oidcScope : oidcScopes) {
            switch (oidcScope.toUpperCase()) {
                case "ADDRESS":
                    this.scope.add(OIDCScopeValue.ADDRESS);
                    break;
                case "EMAIL":
                    this.scope.add(OIDCScopeValue.EMAIL);
                    break;
                case "OFFLINE_ACCESS":
                    this.scope.add(OIDCScopeValue.OFFLINE_ACCESS);
                    break;
                case "PHONE":
                    this.scope.add(OIDCScopeValue.PHONE);
                    break;
                case "PROFILE":
                    this.scope.add(OIDCScopeValue.PROFILE);
                    break;
                default:
            }
        }
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Prompt value.
     * 
     * @param oidcPrompt OpenId Prompt values
     */
    public void setPrompt(String oidcPrompt) {
        log.trace("Entering");
        this.prompt = new Prompt(oidcPrompt);
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId ACR values.
     * 
     * @param oidcAcrs OpenId ACR values
     */
    public void setAcr(List<String> oidcAcrs) {
        log.trace("Entering");
        for (String oidcAcr : oidcAcrs) {
            ACR acr = new ACR(oidcAcr);
            if (this.acrs == null) {
                this.acrs = new ArrayList<ACR>();
            }
            this.acrs.add(acr);
        }
        log.trace("Leaving");
    }

    /**
     * Setter for OpenId Display value.
     * 
     * @param oidcDisplay OpenId Display values
     */
    public void setDisplay(String oidcDisplay) {
        log.trace("Entering");
        try {
            this.display = Display.parse(oidcDisplay);
        } catch (ParseException e) {
            log.error("Could not set display value", e);
        }
        log.trace("Leaving");
    }

    /**
     * Set the lookup strategy for the {@link AttributeContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setAttributeContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AttributeContext> strategy) {
        log.trace("Entering");
        attributeContextLookupStrategy =
                Constraint.isNotNull(strategy, "AttributeContext lookup strategy cannot be null");
        log.trace("Leaving");
    }

    /**
     * Returns the first found string value for attribute.
     * 
     * @param oidcCtx to look attributes for
     * @param name of the attribute
     * @return attribute value if found, null otherwise
     */
    private String attributeToString(@Nonnull final OpenIDConnectContext oidcCtx, String name) {
        log.trace("Entering");
        if (oidcCtx.getResolvedIdPAttributes() == null) {
            log.warn("Attribute context not available");
            log.trace("Leaving");
            return null;
        }
        IdPAttribute attribute = oidcCtx.getResolvedIdPAttributes().get(name);
        if (attribute == null || attribute.getValues().size() == 0) {
            log.debug("attribute " + name + " not found or has no values");
            log.trace("Leaving");
            return null;
        }
        for (IdPAttributeValue attrValue : attribute.getValues()) {
            if (attrValue instanceof StringAttributeValue) {
                log.trace("Leaving");
                // We set the value
                return attrValue.getDisplayValue();
            }
        }
        log.trace("Leaving");
        return null;
    }

    /**
     * Constructs the id token.
     * 
     * @param oidcCtx to look values for
     * @return id token.
     */
    private JSONObject buildIDToken(@Nonnull final OpenIDConnectContext oidcCtx) {
        log.trace("Entering");
        JSONObject idToken = new JSONObject();
        for (Map.Entry<String, String> entry : requestClaims.entrySet()) {
            String value = entry.getValue();
            String claim = entry.getKey();
            if (value == null) {
                // 1. null value
                log.debug("Setting claim " + claim + " to null");
                idToken.put(entry.getKey(), value);
                continue;
            }
            log.debug("locating attribute for " + value);
            String attrValue = attributeToString(oidcCtx, value);
            if (attrValue != null) {
                // 2. attribute value
                log.debug("Setting claim " + claim + " to value " + attrValue);
                idToken.put(claim, attrValue);
                continue;
            }
            if ("essential".equals(value)) {
                // 3. essential value
                JSONObject obj = new JSONObject();
                obj.put("essential", true);
                log.debug("Setting claim " + claim + " to value " + obj.toJSONString());
                idToken.put(claim, obj);
                continue;
            }
            // 4. string value
            log.debug("Setting claim " + claim + " to value " + value);
            idToken.put(claim, value);
        }
        log.trace("Leaving");
        return idToken;
    }

    /**
     * Must be called as a last step before constructing request.
     * 
     * Creates request object. If signing key is present adds also state and iat claims and then signs it.
     * 
     * 
     * @param oidcCtx for accessing attributes.
     * @param state to be added to request object.
     * @return request object
     * @throws Exception if attribute context is not available or parsing/signing fails.
     */
    private JWT getRequestObject(@Nonnull final OpenIDConnectContext oidcCtx, State state) throws Exception {
        log.trace("Entering");

        if (requestClaims == null || requestClaims.size() == 0) {
            log.trace("Leaving");
            return null;
        }
        JSONObject request = new JSONObject();
        request.put("client_id", clientID.getValue());
        request.put("response_type", responseType.toString());
        if (signPrvKey != null) {
            request.put("iss", clientID.getValue());
            request.put("aud", oIDCProviderMetadata.getIssuer().getValue());
            // If we sign we add also iat and state.
            request.put("state", state.getValue());
            request.put("iat", TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()));
        }
        // Build the id token as instructed.
        JSONObject idToken = buildIDToken(oidcCtx);
        JSONObject claims = new JSONObject();
        claims.put("id_token", idToken);
        request.put("claims", claims);
        log.debug("Request object without signature " + request.toJSONString());
        JWTClaimsSet claimsRequest = JWTClaimsSet.parse(request);
        JWT requestObject = null;
        if (signPrvKey != null) {
            requestObject = new SignedJWT(new JWSHeader.Builder(jwsAlgorithm).keyID(keyID).build(), claimsRequest);
            ((SignedJWT) requestObject).sign(new RSASSASigner(signPrvKey));
            log.debug("created request object: " + requestObject.getParsedString());
        } else {
            requestObject = new PlainJWT(new PlainHeader(), claimsRequest);
        }
        log.trace("Leaving");
        return requestObject;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class, true);
        // We initialize the context
        // If request is passive we override default prompt value
        Prompt ovrPrompt = authenticationContext.isPassive() ? new Prompt(Type.NONE) : prompt;
        oidcCtx.setPrompt(ovrPrompt);
        oidcCtx.setAcrs(acrs);
        oidcCtx.setClientID(clientID);
        oidcCtx.setClientSecret(clientSecret);
        oidcCtx.setDisplay(display);
        oidcCtx.setoIDCProviderMetadata(oIDCProviderMetadata);
        oidcCtx.setRedirectURI(redirectURI);
        State state = new State();
        oidcCtx.setState(state);
        Nonce nonce = new Nonce();
        oidcCtx.setNonce(nonce);

        JWT requestObject = null;
        try {
            // must be called as a last step
            requestObject = getRequestObject(oidcCtx, state);
        } catch (Exception e) {
            // TODO: better error id
            log.error("{} unable to create request object", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (authenticationContext.isForceAuthn()) {
            // We set max age to 0 if forcedauth is set
            // TODO: Currently the underlying library doesn't accept value 0, so
            // we set it to 1
            final int maxAge = 1;
            oidcCtx.setAuthenticationRequestURI(
                    new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
                            .endpointURI(oIDCProviderMetadata.getAuthorizationEndpointURI()).display(display)
                            .acrValues(acrs).requestObject(requestObject).responseMode(ResponseMode.QUERY)
                            .maxAge(maxAge).prompt(ovrPrompt).state(state).nonce(nonce).build().toURI());
        } else {
            oidcCtx.setAuthenticationRequestURI(
                    new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
                            .endpointURI(oIDCProviderMetadata.getAuthorizationEndpointURI()).display(display)
                            .acrValues(acrs).requestObject(requestObject).responseMode(ResponseMode.QUERY)
                            .prompt(ovrPrompt).state(state).nonce(nonce).build().toURI());
        }
        log.trace("Leaving");
        return;
    }

}
