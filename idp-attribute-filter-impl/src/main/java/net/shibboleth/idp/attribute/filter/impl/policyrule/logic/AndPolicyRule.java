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

import java.util.Collection;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;

import net.shibboleth.idp.attribute.filter.AttributeFilterContext;
import net.shibboleth.idp.attribute.filter.AttributeFilterException;
import net.shibboleth.idp.attribute.filter.PolicyRequirementRule;
import net.shibboleth.utilities.java.support.annotation.constraint.NullableElements;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * {@link PolicyRequirementRule} that implements the conjunction of Policy Rules.  That
 * is to say {@link Tristate.TRUE} if every rule returns {@link Tristate.TRUE},
 * {@link Tristate.FAIL} as soon as a rule returns {@link Tristate.FAIL}, and
 * {@link Tristate.FALSE} otherwise.<br/>
 * The standard "fail/false fast" optimization is implemented.
 */
@ThreadSafe
public class AndPolicyRule extends AbstractComposedPolicyRule {

    /**
     * Constructor.
     * 
     * @param composedRules rules being composed
     */
    public AndPolicyRule(@Nullable @NullableElements final Collection<PolicyRequirementRule> composedRules) {
        super(composedRules);
    }

    /**
    * A given rule is considered to have matched if, and only if, TRUE is returned by every composed
    * rule.
    * {@inheritDoc} */
    public Tristate matches(@Nonnull AttributeFilterContext filterContext) throws AttributeFilterException {
        final List<PolicyRequirementRule> rules = getComposedRules();
        
        for (PolicyRequirementRule rule:rules) {
            Tristate match = rule.matches(filterContext);
            if (Tristate.FAIL == match) {
                return Tristate.FAIL;
            } else if (Tristate.FALSE == match) {
                return Tristate.FALSE;
            }
        }
        return Tristate.TRUE;
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (getComposedRules().isEmpty()) {
            throw new ComponentInitializationException("No policy rules supplied to AND");
        }
    }

}