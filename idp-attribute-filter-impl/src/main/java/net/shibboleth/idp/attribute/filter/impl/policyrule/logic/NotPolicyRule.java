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

package net.shibboleth.idp.attribute.filter.impl.policyrule.logic;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;

import net.shibboleth.idp.attribute.filter.AttributeFilterContext;
import net.shibboleth.idp.attribute.filter.AttributeFilterException;
import net.shibboleth.idp.attribute.filter.PolicyRequirementRule;
import net.shibboleth.utilities.java.support.component.AbstractDestructableIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.component.ComponentValidationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

import com.google.common.base.Objects;

/**
 * {@link PolicyRequirementRule} that implements the negation of a matcher. <br/>
 * <br/>
 * if FAIL then FAIL else if TRUE then FALSE else TRUE<br/>
 */
@ThreadSafe
public final class NotPolicyRule extends AbstractDestructableIdentifiableInitializableComponent implements
        PolicyRequirementRule {

    /** The matcher we are negating. */
    private final PolicyRequirementRule negatedRule;

    /**
     * Constructor.
     * 
     * @param rule attribute value matcher to be negated
     */
    public NotPolicyRule(@Nonnull final PolicyRequirementRule rule) {
        negatedRule = Constraint.isNotNull(rule, "Policy Requirement rule can not be null");
    }

    /**
     * Get the matcher that is being negated.
     * 
     * @return matcher that is being negated
     */
    @Nonnull public PolicyRequirementRule getNegtedMatcher() {
        return negatedRule;
    }

    /** {@inheritDoc} */
    public Tristate matches(@Nonnull AttributeFilterContext filterContext) throws AttributeFilterException {
        Tristate match = negatedRule.matches(filterContext);
        if (Tristate.FAIL == match) {
            return Tristate.FAIL;
        } else if (Tristate.FALSE == match) {
            return Tristate.TRUE;
        } else {
            return Tristate.FALSE;
        }   
    }

    /** {@inheritDoc} */
    public void setId(String id) {
        super.setId(id);
    }

    /**
     * Validate the sub component.
     * 
     * @throws ComponentValidationException if any of the child validates failed.
     */
    public void validate() throws ComponentValidationException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        ComponentSupport.validate(negatedRule);
    }

    /** {@inheritDoc} */
    protected void doDestroy() {
        ComponentSupport.destroy(negatedRule);
        super.doDestroy();
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        ComponentSupport.initialize(negatedRule);
    }

    /** {@inheritDoc} */
    public String toString() {
        return Objects.toStringHelper(this).add("Negated Policy Rule", negatedRule).toString();
    }
}