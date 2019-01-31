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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.Live;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * An action that sets username principal and converts any OIDC Standard Claims into {@link IdPAttributePrincipal}s.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class ValidateOIDCAuthentication extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateOIDCAuthentication.class);

    /** Avoid creating multiple principals. */
    @Nonnull private boolean avoidMultiplePrincipal;

    /** the subject received from id token. */
    @Nullable private String oidcSubject;

    /** The JWT Claim Set of the ID Token acquired from the token endpoint. */
    @Nullable private JWTClaimsSet jwtClaims;

    /**
     * In MFA use case prior authentication may have created a usernameprincipal already with value not matching to MFA.
     * 
     * @param avoid true if additional principals should be avoided.
     */
    public void setAvoidMultiplePrincipal(final boolean avoid) {
        avoidMultiplePrincipal = avoid;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext, 
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        log.trace("{}: Prerequisities fulfilled to start doPreExecute", getLogPrefix());

        final OpenIDConnectContext oidcCtx = authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Not able to find oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return false;
        }

        if (oidcCtx.getIDToken() == null) {
            log.error("{} No ID Token in response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return false;
        }
        try {
            //TODO P.S. this will fail if not decrypted JWE. 
            oidcSubject = StringSupport.trimOrNull(oidcCtx.getIDToken().getJWTClaimsSet().getSubject());
            jwtClaims = oidcCtx.getIDToken().getJWTClaimsSet();
        } catch (final ParseException e) {
            log.error("{} unable to parse ID Token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return false;
        }

        if (oidcSubject == null) {
            log.error("{} Subject is null in ID Token response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext, 
            @Nonnull final AuthenticationContext authenticationContext) {
        
        buildAuthenticationResult(profileRequestContext, authenticationContext);
        return;
    }

    /**
     * For each OIDC Standard Claim (OpenID Connect Core 1.0 section 5.1) in the JWT Claim set {@code jwtClaimSet},
     * build a {@link IdPAttributePrincipal} using a {@link StringAttributeValue}.
     * <p>
     * Any claim that is not understood (not in the standard claim set) *will* be ignored.
     * <p>
     * All claims are strings except {@code email_verified} and {code phone_verified) (both booleans), {@code address}
     * (JSON Object), and {@code updated_at} (number). Both booleans are represented as string attribute values, the
     * {@code address} and {@code updated_at} claims are currently ignored.
     * 
     * 
     * @return a list of standard OIDC claims as {@link IdPAttributePrincipal}s.
     */
    @Nonnull 
    @Live
    private List<IdPAttributePrincipal> buildIdPAttributePrincipalsFromStandardClaims() {

        final List<IdPAttributePrincipal> claimPrincipals = new ArrayList<>();
        if (jwtClaims != null) {
            // jwtClaims.getClaims() is never null
            for (final Map.Entry<String, Object> claim : jwtClaims.getClaims().entrySet()) {

                if (UserInfo.getStandardClaimNames().contains(claim.getKey())) {

                    String claimValue = null;
                    if (claim.getValue() instanceof String) {
                        claimValue = StringSupport.trimOrNull((String) claim.getValue());
                    }

                    if (claim.getValue() instanceof Boolean) {
                        claimValue = StringSupport.trimOrNull(Boolean.toString((Boolean) claim.getValue()));
                    }
                    if (claimValue == null) {
                        log.trace("{} JWT Claim [{}] is not of a supported type or is null/empty, ignored",
                                getLogPrefix(), claim);
                        continue;
                    }

                    final IdPAttribute idpAttr = new IdPAttribute(claim.getKey());
                    idpAttr.setValues(Collections.singletonList(new StringAttributeValue(claimValue)));

                    final IdPAttributePrincipal attrPrincipal = new IdPAttributePrincipal(idpAttr);
                    log.trace("{} Constructed IdPAttributePrincipal from OIDC claim [{}]", getLogPrefix(),
                            attrPrincipal);
                    claimPrincipals.add(attrPrincipal);
                }

            }
        }

        return claimPrincipals;

    }

    @Override
    protected Subject populateSubject(@Nonnull final Subject subject) {    
        
        if (avoidMultiplePrincipal && subject.getPrincipals().size() > 0) {
            log.debug("{} Subject already contains principal, not populated", getLogPrefix());

        } else {

            log.debug("{} Setting usernameprincipal to {}", getLogPrefix(), oidcSubject);
            subject.getPrincipals().add(new UsernamePrincipal(oidcSubject));
            subject.getPrincipals().addAll(buildIdPAttributePrincipalsFromStandardClaims());

        }        
        return subject;
    }

}
