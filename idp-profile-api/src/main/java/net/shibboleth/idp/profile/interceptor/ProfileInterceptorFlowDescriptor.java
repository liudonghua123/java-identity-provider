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

package net.shibboleth.idp.profile.interceptor;

import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.profile.FlowDescriptor;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.StorageService;

import com.google.common.base.MoreObjects;
import com.google.common.base.Predicates;

/**
 * A descriptor for a profile interceptor flow.
 * 
 * <p>
 * A profile interceptor flow is designed to be injected into a profile flow to facilitate customization of the profile
 * flow. A profile interceptor flow must include an activation predicate to indicate suitability based on the content of
 * the {@link ProfileRequestContext}.
 * </p>
 */
public class ProfileInterceptorFlowDescriptor extends AbstractIdentifiableInitializableComponent implements
        FlowDescriptor, Predicate<ProfileRequestContext> {

    /** Prefix convention for flow IDs. */
    @Nonnull @NotEmpty public static final String FLOW_ID_PREFIX = "intercept/";
    
    /** Predicate that must be true for this flow to be usable for a given request. */
    @Nonnull private Predicate<ProfileRequestContext> activationCondition;

    /** Storage service for the results generated by this flow. */
    @Nullable private StorageService storageService;

    /** Whether this flow supports non-browser clients. */
    private boolean supportsNonBrowser;

    /** Constructor. */
    public ProfileInterceptorFlowDescriptor() {
        activationCondition = Predicates.alwaysTrue();
        supportsNonBrowser = true;
    }

    /**
     * Set the activation condition in the form of a {@link Predicate} such that iff the condition evaluates to true
     * should the corresponding flow be allowed/possible.
     * 
     * @param condition predicate that controls activation of the flow
     */
    public void setActivationCondition(@Nonnull final Predicate<ProfileRequestContext> condition) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        activationCondition = Constraint.isNotNull(condition, "Activation condition predicate cannot be null");
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
     * Get the storage service.
     * 
     * @return the storage service
     */
    @Nullable public StorageService getStorageService() {
        return storageService;
    }

    /**
     * Set the storage service.
     * 
     * @param service the storage service
     */
    public void setStorageService(@Nonnull final StorageService service) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        storageService = Constraint.isNotNull(service, "Storage service can not be null");
    }

    /** {@inheritDoc} */
    public boolean test(@Nullable final ProfileRequestContext input) {
        return activationCondition.test(input);
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

        if (obj instanceof ProfileInterceptorFlowDescriptor) {
            return getId().equals(((ProfileInterceptorFlowDescriptor) obj).getId());
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("flowId", getId())
                .add("nonBrowserSupported", supportsNonBrowser)
                .toString();
    }

}
