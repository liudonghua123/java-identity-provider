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

package net.shibboleth.idp.authn;

import java.io.IOException;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.principal.PrincipalSupportingComponent;
import net.shibboleth.idp.profile.FlowDescriptor;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.StorageSerializer;

import com.google.common.base.MoreObjects;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;

/**
 * A descriptor for an authentication flow.
 * 
 * <p>
 * A flow models a sequence of profile actions that performs authentication in a particular way and satisfies various
 * constraints that may apply to an authentication request. Some of these constraints are directly exposed as properties
 * of the flow, and others can be found by examining the list of extended {@link Principal}s that the flow exposes.
 * </p>
 */
public class AuthenticationFlowDescriptor extends AbstractIdentifiableInitializableComponent implements
        FlowDescriptor, PrincipalSupportingComponent, Predicate<ProfileRequestContext>,
            StorageSerializer<AuthenticationResult> {

    /** Prefix convention for flow IDs. */
    @Nonnull @NotEmpty public static final String FLOW_ID_PREFIX = "authn/";

    /** Additional allowance for storage of result records to avoid race conditions during use. */
    @Nonnull public static final Duration STORAGE_EXPIRATION_OFFSET;

    /** Whether this flow supports non-browser clients. */
    private boolean supportsNonBrowser;
    
    /** Whether this flow supports passive authentication. */
    private boolean supportsPassive;

    /** Whether this flow supports forced authentication. */
    private boolean supportsForced;
    
    /** Whether this flow allows reuse of its results. */
    @Nonnull private Predicate<ProfileRequestContext> reuseCondition;

    /** Maximum amount of time since first usage that a flow should be considered active. */
    @Nullable private Duration lifetime;

    /** Maximum amount of time since last usage that a flow should be considered active. */
    @Nonnull private Duration inactivityTimeout;

    /**
     * Supported principals, indexed by type, that the flow can produce. Implemented for the moment using the Subject
     * class for convenience to allow for class-based lookup in the {@link #getSupportedPrincipals} method.
     */
    @Nonnull private Subject supportedPrincipals;

    /** Predicate that must be true for this flow to be usable for a given request. */
    @Nonnull private Predicate<ProfileRequestContext> activationCondition;
    
    /** Custom serializer for the results generated by this flow. */
    @Nullable private StorageSerializer<AuthenticationResult> resultSerializer;
    
    /** Weighted sort oredering of custom Principals produced by flow(s). */
    @Nullable @NonnullElements private Map<Principal,Integer> principalWeightMap;

    /** Constructor. */
    public AuthenticationFlowDescriptor() {
        supportsNonBrowser = true;
        reuseCondition = Predicates.alwaysTrue();
        supportedPrincipals = new Subject();
        activationCondition = Predicates.alwaysTrue();
        inactivityTimeout = Duration.ofMinutes(30);
        principalWeightMap = Collections.emptyMap();
    }
    
    /**
     * Get whether this flow supports non-browser clients.
     * 
     * @return whether this flow supports non-browser clients
     */
    public boolean isNonBrowserSupported() {
        return supportsNonBrowser;
    }
    
    /**
     * Set whether this flow supports non-browser clients.
     * 
     * @param isSupported whether this flow supports non-browser clients
     */
    public void setNonBrowserSupported(final boolean isSupported) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        supportsNonBrowser = isSupported;
    }

    /**
     * Get whether this flow supports passive authentication.
     * 
     * @return whether this flow supports passive authentication
     */
    public boolean isPassiveAuthenticationSupported() {
        return supportsPassive;
    }

    /**
     * Set whether this flow supports passive authentication.
     * 
     * @param isSupported whether this flow supports passive authentication
     */
    public void setPassiveAuthenticationSupported(final boolean isSupported) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        supportsPassive = isSupported;
    }

    /**
     * Get whether this flow supports forced authentication.
     * 
     * @return whether this flow supports forced authentication
     */
    public boolean isForcedAuthenticationSupported() {
        return supportsForced;
    }

    /**
     * Set whether this flow supports forced authentication.
     * 
     * @param isSupported whether this flow supports forced authentication.
     */
    public void setForcedAuthenticationSupported(final boolean isSupported) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        supportsForced = isSupported;
    }
    
    /**
     * Get condition controlling whether results from this flow should be reused for SSO.
     * 
     * @return whether results from this flow should be reused for SSO
     * 
     * @since 3.4.0
     */
    @Nonnull public Predicate<ProfileRequestContext> getReuseCondition() {
        return reuseCondition;
    }
    
    /**
     * Set condition controlling whether results from this flow should be reused for SSO.
     * 
     * <p>Defaults to {@link Predicates#alwaysTrue()}.</p>
     * 
     * @param condition condition to set
     * 
     * @since 3.4.0
     */
    public void setReuseCondition(@Nonnull final Predicate<ProfileRequestContext> condition) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        reuseCondition = Constraint.isNotNull(condition, "Predicate cannot be null");
    }

    /**
     * Get the maximum amount of time, since first usage, a flow should be considered active. A null
     * indicates that there is no upper limit on the lifetime on an active flow.
     * 
     * @return maximum amount of time a flow should be considered active
     */
    @Nullable public Duration getLifetime() {
        return lifetime;
    }

    /**
     * Set the maximum amount of time, since first usage, a flow should be considered active. A null value
     * indicates that there is no upper limit on the lifetime on an active flow.
     * 
     * @param flowLifetime the lifetime for the flow
     */
    public void setLifetime(@Nullable final Duration flowLifetime) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isFalse(flowLifetime != null && (flowLifetime.isNegative() || flowLifetime.isZero()),
                "Lifetime must be null or greater than 0");

        lifetime = flowLifetime;
    }

    /**
     * Get the maximum amount of time, since the last usage, a flow should be considered active.
     * 
     * <p>
     * Defaults to 30 minutes.
     * </p>
     * 
     * @return the duration
     */
    @Nonnull public Duration getInactivityTimeout() {
        return inactivityTimeout;
    }

    /**
     * Set the maximum amount of time, since the last usage, a flow should be considered active.
     * 
     * @param timeout the flow inactivity timeout, must be greater than zero
     */
    public void setInactivityTimeout(@Nonnull final Duration timeout) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(timeout, "Inactivity timeout cannot be null");
        Constraint.isFalse(timeout.isNegative() || timeout.isZero(), "Inactivity timeout must be greater than 0");

        inactivityTimeout = timeout;
    }

    /**
     * Check if a result generated by this flow is still active.
     * 
     * @param result {@link AuthenticationResult} to check
     * 
     * @return true iff the result remains valid
     */
    public boolean isResultActive(@Nonnull final AuthenticationResult result) {
        Constraint.isNotNull(result, "AuthenticationResult cannot be null");
        Constraint.isTrue(result.getAuthenticationFlowId().equals(getId()),
                "AuthenticationResult was not produced by this flow");

        final Instant now = Instant.now();
        if (getLifetime() != null && now.isAfter(result.getAuthenticationInstant().plus(getLifetime()))) {
            return false;
        } else if (now.isAfter(result.getLastActivityInstant().plus(getInactivityTimeout()))) {
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override @Nonnull @NonnullElements @Unmodifiable public <T extends Principal> Set<T> getSupportedPrincipals(
            @Nonnull final Class<T> c) {
        return supportedPrincipals.getPrincipals(c);
    }

    /**
     * Get a collection of supported non-user-specific principals that the flow may produce when it operates.
     * 
     * <p>
     * The {@link Collection#remove(java.lang.Object)} method is not supported.
     * </p>
     * 
     * @return a live collection of supported principals
     */
    @Nonnull @NonnullElements public Collection<Principal> getSupportedPrincipals() {
        return Collections2.filter(supportedPrincipals.getPrincipals(), Predicates.notNull());
    }

    /**
     * Set supported non-user-specific principals that the flow may produce when it operates.
     * 
     * @param <T> a type of principal to add, if not generic
     * @param principals supported principals to add
     */
    public <T extends Principal> void setSupportedPrincipals(@Nonnull @NonnullElements final Collection<T> principals) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(principals, "Principal collection cannot be null.");

        supportedPrincipals.getPrincipals().clear();
        supportedPrincipals.getPrincipals().addAll(Collections2.filter(principals, Predicates.notNull()));
    }

    /**
     * Set the activation condition in the form of a {@link Predicate} such that iff the condition evaluates to true
     * should the corresponding flow be allowed/possible.
     * 
     * @param condition predicate that controls activation of the flow
     */
    public void setActivationCondition(@Nonnull final Predicate<ProfileRequestContext> condition) {
        activationCondition = Constraint.isNotNull(condition, "Activation condition predicate cannot be null");
    }

    /** {@inheritDoc} */
    public boolean test(@Nullable final ProfileRequestContext input) {
        return activationCondition.test(input);
    }
    
    /**
     * Set a custom serializer for results produced by this flow.
     * 
     * @param serializer the custom serializer
     */
    public void setResultSerializer(@Nonnull final StorageSerializer<AuthenticationResult> serializer) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        resultSerializer = Constraint.isNotNull(serializer, "StorageSerializer cannot be null");
    }
    
    /**
     * Set the map of Principals to weight values to impose a sort order on any matching Principals
     * found in the authentication result.
     * 
     * <p>This was moved from a stand-alone bean into the descriptor beans in order to eliminate
     * stand-alone beans from the flow descriptor configuration files(s).</p>
     * 
     * @param map   map to set
     * 
     * @since 4.0.0
     */
    public void setPrincipalWeightMap(@Nullable @NonnullElements final Map<Principal,Integer> map) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        principalWeightMap = map != null ? map : Collections.<Principal,Integer>emptyMap();
    }    

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (resultSerializer == null) {
            throw new ComponentInitializationException("AuthenticationResult serializer cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override @Nonnull @NotEmpty public String serialize(@Nonnull final AuthenticationResult instance)
            throws IOException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        return resultSerializer.serialize(instance);
    }

    /** {@inheritDoc} */
    @Override @Nonnull public AuthenticationResult deserialize(final long version,
            @Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key, 
            @Nonnull @NotEmpty final String value, @Nonnull final Long expiration)
            throws IOException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);

        // Back the expiration off by the inactivity timeout to recover the last activity time.
        return resultSerializer.deserialize(version, context, key, value, (expiration != null) ? expiration
                - inactivityTimeout.toMillis() - STORAGE_EXPIRATION_OFFSET.toMillis() : null);
    }

    /**
     * Apply the current weighted map to find the highest-weighted object amongst the inputs.
     * 
     * @param <T> principal type
     * @param principals input collection
     * @return the highest weighted as governed by the map set via {@link #setPrincipalWeightMap(Map)}
     * 
     * @since 4.0.0
     */
    @Nullable public <T extends Principal> T getHighestWeighted(
            @Nonnull @NonnullElements final Collection<T> principals) {
        if (principals.isEmpty()) {
            return null;
        } else if (principalWeightMap.isEmpty() || principals.size() == 1) {
            return principals.iterator().next();
        } else {
            final Object[] principalArray = principals.toArray();
            Arrays.sort(principalArray, new WeightedComparator<>());
            return (T) principalArray[principalArray.length - 1];
        }
    }

    /** {@inheritDoc} */
    @Override public int hashCode() {
        return getId().hashCode();
    }

    /** {@inheritDoc} */
    @Override public boolean equals(final Object obj) {
        if (obj == null) {
            return false;
        }

        if (obj == this) {
            return true;
        }

        if (obj instanceof AuthenticationFlowDescriptor) {
            return getId().equals(((AuthenticationFlowDescriptor) obj).getId());
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override public String toString() {
        return MoreObjects.toStringHelper(this).add("flowId", getId()).add("supportsPassive", supportsPassive)
                .add("supportsForcedAuthentication", supportsForced)
                .add("lifetime", lifetime).add("inactivityTimeout", inactivityTimeout).toString();
    }
    
    /**
     * A {@link Comparator} that compares the mapped weights of the two operands, using a weight of zero
     * for any unmapped values.
     * 
     * @param <T> object type
     */
    private class WeightedComparator<T> implements Comparator<T> {

        /** {@inheritDoc} */
        @Override
        public int compare(final T o1, final T o2) {
            
            final int weight1 = principalWeightMap.containsKey(o1) ? principalWeightMap.get(o1) : 0;
            final int weight2 = principalWeightMap.containsKey(o2) ? principalWeightMap.get(o2) : 0;
            if (weight1 < weight2) {
                return -1;
            } else if (weight1 > weight2) {
                return 1;
            }
            
            return 0;
        }
        
    }
    
    static {
        STORAGE_EXPIRATION_OFFSET = Duration.ofMinutes(10);
    }
}