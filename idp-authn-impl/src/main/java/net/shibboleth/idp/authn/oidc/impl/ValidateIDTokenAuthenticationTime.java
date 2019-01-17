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
import java.util.Date;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonNegative;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.joda.time.DateTime;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that verifies Authentication Time of ID Token.
 * 
 * @event {@link net.shibboleth.idp.authn.AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class ValidateIDTokenAuthenticationTime extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateIDTokenAuthenticationTime.class);

    /**
     * Clock skew - milliseconds before a lower time bound, or after an upper time bound, to consider still acceptable
     * Default value: 3 minutes.
     */
    @Duration
    @NonNegative
    private long clockSkew;

    /**
     * Amount of time in milliseconds for which a forced authentication is valid after it is issued. Default value: 30
     * seconds.
     */
    @Duration
    @NonNegative
    private long authnLifetime;

    /**
     * Constructor.
     */
    public ValidateIDTokenAuthenticationTime() {
        super();
        setClockSkew(60 * 3 * 1000);
        setAuthnLifetime(30 * 1000);
    }

    /**
     * Get the clock skew.
     * 
     * @return the clock skew
     */
    @NonNegative
    public long getClockSkew() {
        return clockSkew;
    }

    /**
     * Set the clock skew.
     * 
     * @param skew clock skew to set
     */
    public void setClockSkew(@Duration @NonNegative final long skew) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        clockSkew = Constraint.isGreaterThanOrEqual(0, skew, "Clock skew must be greater than or equal to 0");
    }

    /**
     * Gets the amount of time, in milliseconds, for which a forced authentication is valid.
     * 
     * @return amount of time, in milliseconds, for which a forced authentication is valid
     */
    @NonNegative
    public long getAuthnLifetime() {
        return authnLifetime;
    }

    /**
     * Sets the amount of time, in milliseconds, for which a forced authentication is valid.
     * 
     * @param lifetime amount of time, in milliseconds, for which a forced authentication is valid
     */
    public synchronized void setAuthnLifetime(@Duration @NonNegative final long lifetime) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        authnLifetime =
                Constraint.isGreaterThanOrEqual(0, lifetime, "Authn lifetime must be greater than or equal to 0");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        

        if (!authenticationContext.isForceAuthn()) {
           
            return;
        }
        // If we have forced authentication, we will check for authentication age
        final OpenIDConnectContext oidcCtx =
                authenticationContext.getSubcontext(OpenIDConnectContext.class);
        if (oidcCtx == null) {
            log.error("{} Not able to find oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            
            return;
        }
        final Date authTimeDate;
        try {
            authTimeDate = oidcCtx.getIDToken().getJWTClaimsSet().getDateClaim("auth_time");
        } catch (final ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        if (authTimeDate == null) {
            log.error("{} max age set but no auth_time received", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        final DateTime authTime = new DateTime(authTimeDate);
        final DateTime now = new DateTime();
        final DateTime latestValid = now.plus(getClockSkew());
        final DateTime expiration = authTime.plus(getClockSkew() + getAuthnLifetime());

        // Check authentication wasn't performed in the future
        // Based on org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler
        if (authTime.isAfter(latestValid)) {
            log.warn("{} Authentication time was not yet valid: time was {}, latest valid is: {}", getLogPrefix(),
                    authTime, latestValid);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);           
            return;
        }

        // Check authentication time has not expired
        if (expiration.isBefore(now)) {
            log.warn("{} Authentication time was expired: time was '{}', expired at: '{}', current time: '{}'",
                    getLogPrefix(), authTime, expiration, now);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);            
            return;
        }
        
    }

}