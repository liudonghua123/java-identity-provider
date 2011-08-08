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

package net.shibboleth.idp.attribute.filtering;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;
import net.shibboleth.idp.attribute.Attribute;

import org.opensaml.util.StringSupport;
import org.opensaml.util.collections.CollectionSupport;
import org.opensaml.util.collections.LazyList;
import org.opensaml.util.collections.LazySet;
import org.opensaml.util.component.AbstractIdentifiedInitializableComponent;
import org.opensaml.util.component.ComponentInitializationException;
import org.opensaml.util.component.ComponentValidationException;
import org.opensaml.util.component.DestructableComponent;
import org.opensaml.util.component.UnmodifiableComponent;
import org.opensaml.util.component.UnmodifiableComponentException;
import org.opensaml.util.component.ValidatableComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//TODO perf metrics

/** Services that filters out attributes and values based upon loaded policies. */
@ThreadSafe
public class AttributeFilteringEngine extends AbstractIdentifiedInitializableComponent implements ValidatableComponent,
        DestructableComponent, UnmodifiableComponent {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AttributeFilteringEngine.class);

    /** Filter policies used by this engine. */
    private Set<AttributeFilterPolicy> filterPolicies = Collections.EMPTY_SET;

    /** {@inheritDoc} */
    public synchronized void setId(final String componentId) {
        super.setId(componentId);
    }

    /**
     * Gets the immutable collection of filter policies.
     * 
     * @return immutable collection of filter policies, never null or containing null elements
     */
    public Set<AttributeFilterPolicy> getFilterPolicies() {
        return filterPolicies;
    }

    /**
     * Sets the new policies for the filtering engine.
     * 
     * @param policies new policies for the filtering engine, may be null or contain null elements
     */
    public synchronized void setFilterPolicies(final Collection<AttributeFilterPolicy> policies) {
        if (isInitialized()) {
            throw new UnmodifiableComponentException("Attribute filter egine " + getId()
                    + " has already been initialized, its filter policies can not be changed.");
        }

        LazySet<AttributeFilterPolicy> newPolicies =
                CollectionSupport.addNonNull(policies, new LazySet<AttributeFilterPolicy>());
        filterPolicies = Collections.unmodifiableSet(newPolicies);
    }

    /** {@inheritDoc} */
    public void validate() throws ComponentValidationException {
        final LazyList<String> invalidPolicyIds = new LazyList<String>();
        final Set<AttributeFilterPolicy> policies = getFilterPolicies();
        for (AttributeFilterPolicy policy : policies) {
            try {
                log.debug("Attribute filtering engine {}: checking if policy {} is valid", getId(), policy.getId());
                policy.validate();
                log.debug("Attribute filtering engine {}: policy {} is valid", getId(), policy.getId());
            } catch (ComponentValidationException e) {
                log.warn("Attribute filtering engine {}: filter policy {} is not valid", new Object[] {this.getId(),
                        policy.getId(), e,});
                invalidPolicyIds.add(policy.getId());
            }
        }

        if (!invalidPolicyIds.isEmpty()) {
            throw new ComponentValidationException("The following attribute filter policies were invalid: "
                    + StringSupport.listToStringValue(invalidPolicyIds, ", "));
        }
    }

    /** {@inheritDoc} */
    public synchronized void destroy() {
        final Set<AttributeFilterPolicy> policies = getFilterPolicies();
        for (AttributeFilterPolicy policy : policies) {
            policy.destroy();
        }

        filterPolicies = Collections.emptySet();
    }

    /**
     * Filters attributes and values. This filtering process may remove attributes and values but must never add them.
     * 
     * @param filterContext context containing the attributes to be filtered and collecting the results of the filtering
     *            process
     * 
     * @throws AttributeFilteringException thrown if there is a problem retrieving or applying the attribute filter
     *             policy
     */
    public void filterAttributes(final AttributeFilterContext filterContext) throws AttributeFilteringException {
        if (!isInitialized()) {
            throw new AttributeFilteringException("Attribute filtering engine " + getId()
                    + " has not be initialized and can not yet be used");
        }

        final Set<AttributeFilterPolicy> policies = getFilterPolicies();
        for (AttributeFilterPolicy policy : policies) {
            if (!policy.isApplicable(filterContext)) {
                log.debug("Attribute filtering engine {}: filter policy {} is not applicable", getId(), policy.getId());
            }

            log.debug("Attribute filtering engine {}: applying filter policy {}", getId(), policy.getId());
            policy.apply(filterContext);
            log.debug("Attribute filtering engine {}: attributes available after applying filter policy {}: {}",
                    new Object[] {getId(), policy.getId(), filterContext.getFilteredAttributes()});
        }

        Collection<?> filteredAttributeValues;
        Attribute filteredAttribute;
        for (String attributeId : filterContext.getPermittedAttributeValues().keySet()) {
            filteredAttributeValues = getFilteredValues(attributeId, filterContext);
            if (filteredAttributeValues != null) {
                filteredAttribute = filterContext.getPrefilteredAttributes().get(attributeId).clone();
                filteredAttribute.setValues(filteredAttributeValues);
                filterContext.addFilteredAttribute(filteredAttribute);
            }
        }
    }

    /**
     * Gets the permitted values for the given attribute from the
     * {@link AttributeFilterContext#getPermittedAttributeValues()} and removes all denied values given in the
     * {@link AttributeFilterContext#getDeniedAttributeValues()}.
     * 
     * @param attributeId ID of the attribute whose values are to be retrieved
     * @param filterContext current attribute filter context
     * 
     * @return the values which are permitted to be released and not denied or null if no values are allowed to be
     *         released
     */
    protected Collection<?> getFilteredValues(final String attributeId, final AttributeFilterContext filterContext) {
        final Collection<?> filteredAttributeValues = filterContext.getPermittedAttributeValues().get(attributeId);
        if (filteredAttributeValues == null || filteredAttributeValues.isEmpty()) {
            return null;
        }

        if (filterContext.getDeniedAttributeValues().containsKey(attributeId)) {
            filteredAttributeValues.removeAll(filterContext.getDeniedAttributeValues().get(attributeId));
        }

        if (filteredAttributeValues == null || filteredAttributeValues.isEmpty()) {
            return null;
        }

        return filteredAttributeValues;
    }
    
    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        for(AttributeFilterPolicy policy : filterPolicies){
            policy.initialize();
        }
    }
}