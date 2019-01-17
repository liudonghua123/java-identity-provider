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
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;

/**
 * An action that verifies Signature of ID Token.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre
 * 
 *      <pre>
 *      AuthenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class, false) != null
 *      </pre>
 * 
 *      AND
 * 
 *      <pre>
 *      SocialUserOpenIdConnectContext.getOidcTokenResponse() != null
 *      </pre>
 * 
 *      AND
 * 
 *      <pre>
 *      SocialUserOpenIdConnectContext.getoIDCProviderMetadata() != null
 *      </pre>
 */
@SuppressWarnings("rawtypes")
public class ValidateIDTokenSignature extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateIDTokenSignature.class);



    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull
    final ProfileRequestContext profileRequestContext, @Nonnull
    final AuthenticationContext authenticationContext) {
        log.trace("Entering");
        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        SignedJWT signedJWT = null;
        try {
            signedJWT = SignedJWT.parse(oidcCtx.getIDToken().serialize());
        } catch (ParseException e) {
            log.error("{} Error when forming signed JWT", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        RSAPublicKey providerKey = null;
        try {
            JSONObject key = getProviderRSAJWK(oidcCtx.getoIDCProviderMetadata().getJWKSetURI().toURL().openStream(),
                    signedJWT.getHeader().getKeyID());
            if (key == null) {
                log.error("{} Not able to find key to verify signature", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
            providerKey = RSAKey.parse(key).toRSAPublicKey();
        } catch (IOException | java.text.ParseException | JOSEException e) {
            log.error("{} Error when parsing key to verify signature", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        RSASSAVerifier verifier = new RSASSAVerifier(providerKey);
        try {
            if (!signedJWT.verify(verifier)) {
                log.error("{} JWT signature verification failed", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
        } catch (JOSEException e) {
            log.error("{} JWT signature verification not performed", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.debug("ID Token signature verified");
        log.trace("Leaving");
        return;
    }

    /**
     * Parse JWK, RSA public key for signature verification, from stream.
     * 
     * @param is inputstream containing the key
     * @param kid The key ID to be looked after
     * @return RSA public key as JSON Object. Null if there is no key
     * @throws ParseException if parsing fails.
     * @throws IOException if something unexpected happens.
     */
    @Nullable
    private JSONObject getProviderRSAJWK(final InputStream is, final String kid) throws ParseException, IOException {
        log.trace("Entering");
        if (kid == null) {
            log.warn("No kid defined in the JWT, no kid check can be performed!");
        }

        StringWriter writer = new StringWriter();
        CharStreams.copy(new InputStreamReader(is, Charsets.UTF_8), writer);

        JSONObject json = JSONObjectUtils.parse(writer.toString());
        JSONArray keyList = (JSONArray) json.get("keys");
        if (keyList == null) {
            log.trace("Leaving");
            return null;
        }
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if ("sig".equals(k.get("use")) && "RSA".equals(k.get("kty"))) {
                if (kid == null || kid.equals(k.get("kid"))) {
                    log.debug("verification key " + k.toString());
                    log.trace("Leaving");
                    return k;
                }
            }
        }
        log.trace("Leaving");
        return null;
    }

}
