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

package net.shibboleth.idp.relyingparty;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.IdentifiableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

/** The configuration that applies to a given relying party. */
public class RelyingPartyConfiguration implements IdentifiableComponent, Predicate<ProfileRequestContext> {

    /** Unique identifier for this configuration. */
    @Nonnull @NotEmpty private final String id;

    /** The entity ID of the IdP. */
    @Nonnull @NotEmpty private final String responderEntityId;
    
    /** Controls whether detailed information about errors should be exposed. */
    private final boolean detailedErrors; 

    /** Registered and usable communication profile configurations for this relying party. */
    @Nonnull @NonnullElements private final Map<String, ProfileConfiguration> profileConfigurations;

    /** Predicate that must be true for this configuration to be active for a given request. */
    @Nonnull private final Predicate<ProfileRequestContext> activationCondition;
    
    /**
     * Constructor.
     * 
     * @param configurationId unique ID for this configuration
     * @param responderId the ID by which the responder is known by this relying party
     * @param detailedErrorsFlag whether detailed information about errors should be exposed
     * @param configurations communication profile configurations for this relying party
     * @param condition criteria that must be met in order for this relying party configuration to apply to a given
     *            profile request
     */
    public RelyingPartyConfiguration(@Nonnull @NotEmpty final String configurationId,
            @Nonnull @NotEmpty final String responderId, final boolean detailedErrorsFlag,
            @Nonnull @NonnullElements final Collection<? extends ProfileConfiguration> configurations,
            @Nonnull final Predicate<ProfileRequestContext> condition) {
        
        id = Constraint.isNotNull(StringSupport.trimOrNull(configurationId),
                "Relying party configuration ID cannot be null or empty");
        responderEntityId = Constraint.isNotNull(StringSupport.trimOrNull(responderId),
                "Responder entity ID cannot be null or empty");
        detailedErrors = detailedErrorsFlag;
        activationCondition = Constraint.isNotNull(condition,
                "Relying partying configuration activation condition cannot be null");
        
        if (configurations == null || configurations.isEmpty()) {
            profileConfigurations = Collections.emptyMap();
            return;
        }

        profileConfigurations = Maps.newHashMap();
        
        for (ProfileConfiguration config : Collections2.filter(configurations, Predicates.notNull())) {
            final String trimmedId = Constraint.isNotNull(StringSupport.trimOrNull(config.getId()),
                    "ID of profile configuration class " + config.getClass().getName() + " cannot be null");
            profileConfigurations.put(trimmedId, config);
        }
    }

    /**
     * Constructor.
     * 
     * @param configurationId unique ID for this configuration
     * @param responderId the ID by which the responder is known by this relying party
     * @param detailedErrorsFlag whether detailed information about errors should be exposed
     * @param configurations communication profile configurations for this relying party
     */
    public RelyingPartyConfiguration(@Nonnull @NotEmpty final String configurationId,
            @Nonnull @NotEmpty final String responderId, final boolean detailedErrorsFlag,
            @Nonnull @NonnullElements final Collection<? extends ProfileConfiguration> configurations) {
        this(configurationId, responderId, detailedErrorsFlag, configurations,
                Predicates.<ProfileRequestContext>alwaysTrue());
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull @NotEmpty public String getId() {
        return id;
    }

    /**
     * Get the ID of the entity responding to requests.
     * 
     * @return ID of the entity responding to requests
     */
    @Nonnull @NotEmpty public String getResponderEntityId() {
        return responderEntityId;
    }
    
    /**
     * Get whether detailed information about errors should be exposed.
     * 
     * @return true iff it is acceptable to expose detailed error information
     */
    public boolean isDetailedErrors() {
        return detailedErrors;
    }

    /**
     * Get the unmodifiable set of profile configurations for this relying party.
     * 
     * @return unmodifiable set of profile configurations for this relying party, never null
     */
    @Nonnull @NonnullElements @Unmodifiable @NotLive
    public Map<String, ProfileConfiguration> getProfileConfigurations() {
        return ImmutableMap.copyOf(profileConfigurations);
    }

    /**
     * Get the profile configuration, for the relying party, for the given profile. This is a convenience method and is
     * equivalent to calling {@link Map#get(Object)} on the return of {@link #getProfileConfigurations()}. This map
     * contains no null entries, keys, or values.
     * 
     * @param profileId the ID of the profile
     * 
     * @return the configuration for the profile or null if the profile ID was null or empty or there is no
     *         configuration for the given profile
     */
    @Nullable public ProfileConfiguration getProfileConfiguration(@Nullable final String profileId) {
        final String trimmedId = StringSupport.trimOrNull(profileId);
        if (trimmedId == null) {
            return null;
        }

        return profileConfigurations.get(trimmedId);
    }
    
    /** {@inheritDoc} */
    @Override
    public boolean apply(@Nullable final ProfileRequestContext input) {
        return activationCondition.apply(input);
    }
    
}