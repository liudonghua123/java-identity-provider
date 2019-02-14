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
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;

/**
 * An action that verifies the signature of a JWS id_token using the RSA key belonging to the keyID
 * found in the JOSE Header.
 * 
 * <p>The current implementation *requires* the id_token is signed, and *requires* an RSA key type</p>
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @pre <pre>AuthenticationContext.getSubcontext(OpenIDConnectContext.class, false) != null</pre>
 * @pre <pre>OpenIdConnectContext.getoIDCProviderMetadata() != null</pre>
 * 
 * @since 4.0.0
 */
public class ValidateIDTokenSignature extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateIDTokenSignature.class);

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
        SignedJWT signedJWT = null;
        try {
            //TODO P.S. oidcCtx.getIDToken() could be null.
            signedJWT = SignedJWT.parse(oidcCtx.getIDToken().serialize());
        } catch (final ParseException e) {
            log.error("{} Error when parsing signed JWT", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        RSAPublicKey providerKey = null;
        try {
            final JSONObject key = getProviderRSAJWK(oidcCtx.getoIDCProviderMetadata().getJWKSetURI()
                    .toURL().openStream(),signedJWT.getHeader().getKeyID());
            if (key == null) {
                log.error("{} Unable to find key to verify signature", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);                
                return;
            }
            providerKey = RSAKey.parse(key).toRSAPublicKey();
        } catch (final IOException | java.text.ParseException | JOSEException e) {
            log.error("{} Error when parsing key to verify signature", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        final RSASSAVerifier verifier = new RSASSAVerifier(providerKey);
        try {
            if (!signedJWT.verify(verifier)) {
                log.error("{} JWT signature verification failed", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);               
                return;
            }
        } catch (final JOSEException e) {
            log.error("{} JWT signature verification not performed", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        log.debug("{} ID Token signature verified",getLogPrefix());        
        return;
    }

    /**
     * Parse JWK and RSA public key from the input stream for signature verification.
     * 
     * @param is inputstream containing the JWK
     * @param kid The key ID to be looked up
     * @return RSA public key as a JSON Object. <code>Null</code> if there is no key
     * @throws ParseException if parsing fails.
     * @throws IOException if something unexpected happens.
     */
    //TODO could be cached? (or use Nimbus to do this validation as it does cache it). 
    @Nullable
    private JSONObject getProviderRSAJWK(@Nonnull final InputStream is, @Nullable final String kid) 
            throws ParseException, IOException {
        
        if (kid == null) {
            log.warn("No kid defined in the JWT, no signning key can be returned");
        }

        final StringWriter writer = new StringWriter();
        CharStreams.copy(new InputStreamReader(is, Charsets.UTF_8), writer);

        final JSONObject json = JSONObjectUtils.parse(writer.toString());
        final JSONArray keyList = (JSONArray) json.get("keys");
        if (keyList == null) {            
            return null;
        }
        for (final Object key : keyList) {
            final JSONObject k = (JSONObject) key;
            if ("sig".equals(k.get("use")) && "RSA".equals(k.get("kty"))) {
                if (kid == null || kid.equals(k.get("kid"))) {                                   
                    return k;
                }
            }
        }        
        return null;
    }

}
