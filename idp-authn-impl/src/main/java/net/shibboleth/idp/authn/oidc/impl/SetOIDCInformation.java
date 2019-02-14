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
import javax.annotation.Nullable;

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
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * 
 * An action that populates the {@link AuthenticationContext} with a freshly built {@link OpenIDConnectContext}.
 * 
 * <p>A singleton instance of this class can be created and shared between authentication requests.</p>
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class) != null</pre>
 * @post The AuthenticationContext is modified as above.
 * 
 * @since 4.0.0
 */
@SuppressWarnings("rawtypes")
public class SetOIDCInformation extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(SetOIDCInformation.class);

    /** Context to look attributes for. */
    @Nonnull private Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy;

    /** Redirect URI. */
    @Nonnull private URI redirectURI;

    /** Client Id. */
    @Nonnull private ClientID clientID;

    /** Client Secret. */
    @Nonnull private Secret clientSecret;

    /** Response type, default is code flow. */
    @Nonnull private ResponseType responseType = new ResponseType(ResponseType.Value.CODE);

    /** Scope. Must contain an openid scope.*/
    @Nonnull private Scope scope = new Scope(OIDCScopeValue.OPENID);

    /**
     *  OIDC Prompt. Specifies whether the Authorization Server prompts
     *  the End-User for reauthentication and consent.
     */
    @Nullable private Prompt prompt;

    /** OIDC Authentication Class Reference values. */
    @Nullable @NonnullElements private List<ACR> acrs;

    /**
     *  OIDC Display. Value that specifies how the Authorization Server
     *  displays the authentication and consent user interface pages to the End-User. 
     */
    @Nullable private Display display;

    /** Private key for signing the request object. */
    @Nullable private PrivateKey signPrvKey;

    /** Algorithm used for signing the request object. Defaults to the required
     * singing algorithm of RSA SHA-256*/
    @Nonnull private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

    /** key id for key used for signing the request object. */
    @Nonnull private String keyID = "id";

    /** Request object claims. */
    @Nullable private Map<String, String> requestClaims;

    /** OIDC provider metadata. */
    @Nonnull private OIDCProviderMetadata oIDCProviderMetadata;

    /** Constructor. */
    public SetOIDCInformation() {        
        attributeContextLookupStrategy = Functions.compose(new ChildContextLookup<>(AttributeContext.class),
                new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));        
        
    }

    /**
     * Set the private key used for signing request object.
     * 
     * @param key signing key
     */
    public void setPrivKey(@Nullable final PrivateKey key) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);     
        signPrvKey = key;
    }

    /**
     * Set the RSA algorithm used for signing the request object. Default is RS256.
     * 
     * @param algorithm used for signing, must not be <code>null</code>.
     */
    public void setJwsAlgorithm(@Nonnull final JWSAlgorithm algorithm) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);   
        jwsAlgorithm = Constraint.isNotNull(algorithm,"OpenID Connect JWS Request algorithm can not be null");
       
    }

    /**
     * Set the key id of the key.
     * 
     * @param id for the key, must not be <code>null</code>.
     */
    public void setKeyID(@Nonnull @NotEmpty final String id) {        
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);        
        keyID =Constraint.isNotNull(StringSupport.trimOrNull(id), "OpenID Connect key ID cannot be null");       
    }

    /**
     * 
     * If this is set (i.e. not <code>null</code>) request claims will be built as a
     * JWT Request Object. See OpenID Connect Core section 6.1. If the <code>signPrvKey</code>
     * is set, the JWT will also be signed.
     * 
     * <p>The key of the mapping is the name of the requested claim. The value of the requested claim
     * is either:
     * <ul>
     * <li>Null, if the claim is being requested in a default manor</li>   
     * <li><code>{"essential":true}</code> if the value is essential. The default is 
     * <code>{"essential":false}</code></li>
     * <li>A specific value for the claim. This value must be a valid value for that claim.</li>
     * <li>A specific set of values for the claim. These values must be valid value for that claim.</li>
     * </ul>
     * </p>
     * <p>
     * If used, the OpenID Connect Provider must support it, as specified in the 
     * <code>request_parameter_supported</code> parameter of the Providers discovery metadata.
     * 
     * @param claims map of requested claims
     */
    public void setRequestClaims(@Nullable final Map<String, String> claims) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        requestClaims = claims;
    }

    /**
     * Sets the response type. Default is code. 
     * 
     * @param type space-delimited list of one or more authorization response types. Must not be <code>null</code>.
     * @throws ParseException if response type cannot be parsed
     */
    public void setResponseType(@Nonnull @NotEmpty final String type) throws ParseException {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(StringSupport.trimOrNull(type), "OpenID Connect response type cannot be null or empty");
        
        responseType = ResponseType.parse(type);
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param oauth2ClientID Oauth2 Client ID, must not be <code>null</code>.
     */
    public void setClientID(@Nonnull @NotEmpty final String oauth2ClientID) {  
        
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(StringSupport.trimOrNull(oauth2ClientID), 
                "OpenID Connect client ID cannot be null or empty");
               
        clientID = new ClientID(oauth2ClientID);
    }

    /**
     * Setter for OAuth2 Client secret.
     * 
     * @param oauth2ClientSecret OAuth2 Client Secret, must not be <code>null</code>.
     */
    public void setClientSecret(@Nonnull @NotEmpty final String oauth2ClientSecret) {       
        
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(StringSupport.trimOrNull(oauth2ClientSecret), 
                "OpenID Connect client secret cannot be null or empty");
               
        clientSecret = new Secret(oauth2ClientSecret);
    }

    /**
     * Setter for the OAuth 2.0 redirect URI the OIDC provider will return to. The constructed URI should not be empty.
     * 
     * @param redirect OAuth2 redirect uri, must not be <code>null</code>.
     */

    public void setRedirectURI(@Nonnull @NotEmpty final URI redirect) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(redirect, "OpenID Connect redirect URI cannot be null");
        Constraint.isNotEmpty(redirect.toString(), "OpenID Connect redirect URI cannot be empty");
        
        redirectURI = redirect;

    }

    /**
     * Setter for OpenId Provider Metadata resource.
     * 
     * <p>Constructs a URI from the <code>metadataLocation</code> and attempts to connect, 
     * stream, and parse its content into an {@link OIDCProviderMetadata} instance.</p>
     * 
     * @param metadataLocation OpenId Provider Metadata location, must not be <code>null</code>.
     * 
     * @throws URISyntaxException if metadataLocation is not a URI
     * @throws IOException if metadataLocation cannot be read
     * @throws ParseException if metadataLocation has wrong content
     */
    public void setProviderMetadataLocation(@Nonnull @NotEmpty final String metadataLocation)
            throws URISyntaxException, IOException, ParseException {

        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(StringSupport.trimOrNull(metadataLocation), 
                "OpenID Connect metadata location cannot be null or empty");
        
        final URI issuerURI = new URI(metadataLocation);
        final URL providerConfigurationURL = issuerURI.resolve(".well-known/openid-configuration").toURL();
        final InputStream stream = providerConfigurationURL.openStream();
        String providerInfo = null;
        try (java.util.Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        }
        oIDCProviderMetadata = OIDCProviderMetadata.parse(providerInfo);
        
    }

    /**
     * Setter for OpenId Scope values. New ones are be added to the {@value OIDCScopeValue#OPENID} scope.
     * 
     * @param oidcScopes OpenID Connect Scope values, can be <code>null</code> and will be ignored.
     */
    public void setScope(@Nullable final List<String> oidcScopes) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        //As the OPENID scope is always set. New scopes can be null.
        if (oidcScopes==null) {
            return;
        }
        
        for (final String oidcScope : oidcScopes) {
            switch (oidcScope.toUpperCase()) {
                case "ADDRESS":
                    scope.add(OIDCScopeValue.ADDRESS);
                    break;
                case "EMAIL":
                    scope.add(OIDCScopeValue.EMAIL);
                    break;
                case "OFFLINE_ACCESS":
                    scope.add(OIDCScopeValue.OFFLINE_ACCESS);
                    break;
                case "PHONE":
                    scope.add(OIDCScopeValue.PHONE);
                    break;
                case "PROFILE":
                    scope.add(OIDCScopeValue.PROFILE);
                    break;
                default:
            }
        }
        
    }

    /**
     * Setter for the OpenID Connect Prompt value.
     * 
     * @param oidcPrompt  OpenID Connect Prompt value.
     */
    public void setPrompt(@Nullable final String oidcPrompt) {    
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        prompt = new Prompt(oidcPrompt);        
    }

    /**
     * Setter for the OpenID Connect Authentication Context Class Reference (ACR) values.
     * 
     * @param oidcAcrs OpenId ACR values
     */
    public void setAcr(@Nullable @NonnullElements final List<String> oidcAcrs) {     
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        if (null != oidcAcrs) {
            for (final String oidcAcr : oidcAcrs) {
                final ACR acr = new ACR(oidcAcr);
                
                if (acrs == null) {
                    acrs = new ArrayList<ACR>();
                }
                if (acr!=null) {
                    acrs.add(acr);
                }
            }
        }
        
    }

    /**
     * Setter for the OpenID Connect Display value.
     * 
     * @param oidcDisplay OpenID Connect Display value.
     */
    public void setDisplay(@Nullable final String oidcDisplay) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        if (null != display) {
             try {
                 display = Display.parse(oidcDisplay);
             } catch (final ParseException e) {
                 log.error("{} Could not set display value",getLogPrefix(), e);
             }
        }
        
    }

    /**
     * Set the lookup strategy for the {@link AttributeContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setAttributeContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AttributeContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        attributeContextLookupStrategy =
                Constraint.isNotNull(strategy, "AttributeContext lookup strategy cannot be null");
        
    }

    /**
     * Returns the first {@link StringAttributeValue} value of the {@link IdPAttribute} that has key 
     * <code>name</code> from the {@link OpenIDConnectContext#getResolvedIdPAttributes()}.
     * 
     * @param oidcCtx context to get attributes from.
     * @param name of the attribute to find.
     * @return attribute value if found, null otherwise.
     */
    @Nullable private String attributeToString(@Nonnull final OpenIDConnectContext oidcCtx, 
            @Nullable final String name) {
        
        if (oidcCtx.getResolvedIdPAttributes() == null) {
            log.warn("Attribute context not available");            
            return null;
        }
        final IdPAttribute attribute = oidcCtx.getResolvedIdPAttributes().get(name);
        if (attribute == null || attribute.getValues().size() == 0) {
            log.debug("attribute " + name + " not found or has no values");            
            return null;
        }
        for (final IdPAttributeValue attrValue : attribute.getValues()) {
            if (attrValue instanceof StringAttributeValue) {               
                // We set the value
                return attrValue.getDisplayValue();
            }
        }        
        return null;
    }

    /**
     * Build the requested claims into an JSONObject, used by 
     * {@link #getRequestObject(OpenIDConnectContext, State)}.
     * 
     * @param oidcCtx context to extract request claims from.
     * @return id token as a JSON Object.
     */
    @Nonnull private JSONObject buildIDToken(@Nonnull final OpenIDConnectContext oidcCtx) {
        
        final JSONObject idToken = new JSONObject();
        for (final Map.Entry<String, String> entry : requestClaims.entrySet()) {
            final String value = entry.getValue();
            final String claim = entry.getKey();
            if (value == null) {
                // 1. null value
                log.debug("Setting claim " + claim + " to null");
                idToken.put(entry.getKey(), value);
                continue;
            }
            log.debug("locating attribute for " + value);
            final String attrValue = attributeToString(oidcCtx, value);
            if (attrValue != null) {
                // 2. attribute value
                log.debug("Setting claim " + claim + " to value " + attrValue);
                idToken.put(claim, attrValue);
                continue;
            }
            if ("essential".equals(value)) {
                // 3. essential value
                final JSONObject obj = new JSONObject();
                obj.put("essential", true);
                log.debug("Setting claim " + claim + " to value " + obj.toJSONString());
                idToken.put(claim, obj);
                continue;
            }
            // 4. string value
            log.debug("Setting claim " + claim + " to value " + value);
            idToken.put(claim, value);
        }
        
        return idToken;
    }

    /**
     * 
     * Construct a JWT claims Request Object (see OpenID Connect core 1.0 section 6) iff claims 
     * are requested i.e. <code>requestClaims</code> is not <code>null</code>. 
     * 
     * <p>If the signing key is present, adds also state, iat claims and then signs it.</p>
     * 
     * <p>Must be called as a last step before constructing the request.</p>
     *  
     * 
     * @param oidcCtx context for accessing attributes.
     * @param state to be added to the request object.
     * @return the request object, or null if one is not constructed.
     * 
     * @throws Exception if attribute context is not available or parsing/signing fails.
     */
    @Nullable private JWT getRequestObject(@Nonnull final OpenIDConnectContext oidcCtx, @Nonnull final State state) 
            throws Exception {
        

        if (requestClaims == null || requestClaims.size() == 0) {            
            return null;
        }
        final JSONObject request = new JSONObject();
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
        final JSONObject idToken = buildIDToken(oidcCtx);
        final JSONObject claims = new JSONObject();
        claims.put("id_token", idToken);
        request.put("claims", claims);
        log.debug("Request object without signature "+getLogPrefix() + request.toJSONString());
        final JWTClaimsSet claimsRequest = JWTClaimsSet.parse(request);
        JWT requestObject = null;
        if (signPrvKey != null) {
            requestObject = new SignedJWT(new JWSHeader.Builder(jwsAlgorithm).keyID(keyID).build(), claimsRequest);
            ((SignedJWT) requestObject).sign(new RSASSASigner(signPrvKey));
            log.debug("created request object: " + requestObject.getParsedString());
        } else {
            requestObject = new PlainJWT(new PlainHeader(), claimsRequest);
        }        
        return requestObject;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        

        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class, true);
        
        // Initialize the context, if request is passive we override default prompt value
        final Prompt ovrPrompt = authenticationContext.isPassive() ? new Prompt(Type.NONE) : prompt;
        oidcCtx.setPrompt(ovrPrompt);
        oidcCtx.setAcrs(acrs);
        oidcCtx.setClientID(clientID);
        oidcCtx.setClientSecret(clientSecret);
        oidcCtx.setDisplay(display);
        oidcCtx.setoIDCProviderMetadata(oIDCProviderMetadata);
        oidcCtx.setRedirectURI(redirectURI);
        final State state = new State();
        oidcCtx.setState(state);
        final Nonce nonce = new Nonce();
        oidcCtx.setNonce(nonce);

        JWT requestObject = null;
        try {
            // must be called as a last step
            requestObject = getRequestObject(oidcCtx, state);
        } catch (final Exception e) {
            // TODO: better error id
            log.error("{} unable to create request object", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
           
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
       
        return;
    }

}
