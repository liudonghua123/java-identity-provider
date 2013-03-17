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

package net.shibboleth.idp.attribute.filtering.impl.matcher;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.Nonnull;

import net.shibboleth.idp.attribute.Attribute;
import net.shibboleth.idp.attribute.AttributeValue;
import net.shibboleth.idp.attribute.filtering.AttributeFilterContext;
import net.shibboleth.idp.attribute.filtering.AttributeFilteringException;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Objects;
import com.google.common.base.Predicate;

/**
 * This is the bases of all implementations of {@link MatchFunctor} which do some sort or element comparison.<br/>
 * <br/>
 * 
 * PolicyRequirementRule implementations will implement the {@link Predicate<AttributeFilterContext>} part and will get
 * a default result for {@link BaseValuePredicateMatcher#getMatchingRules} which states that if the predicate is true
 * then we get all values for the attribute otherwise none.
 * 
 * AttributeRule implementations will extend a superclass of thi:s {@link BaseValuePredicateMatcher} or
 * {@link BaseRegexpValuePredicateMatcher} which will implement a sensible default for the PolicyRequirementRule and
 * inject the required valuePredicate into the constructor.
 */

public abstract class BaseValuePredicateMatcher implements MatchFunctor {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(BaseValuePredicateMatcher.class);

    /** Predicate used to check attribute values. */
    private final Predicate<AttributeValue> valuePredicate;

    /**
     * Constructor. This is only called for AttributeRule type functors
     * 
     * @param valueMatchingPredicate predicate used to check attribute values
     */
    protected BaseValuePredicateMatcher(@Nonnull Predicate<AttributeValue> valueMatchingPredicate) {
        valuePredicate =
                Constraint.isNotNull(valueMatchingPredicate, "Attribute value matching predicate can not be null");
    }

    /**
     * Constructor.
     *
     */
    protected BaseValuePredicateMatcher() {
        valuePredicate = null;
    }

    /** {@inheritDoc} */
    public Set<AttributeValue> getMatchingValues(@Nonnull Attribute attribute,
            @Nonnull AttributeFilterContext filterContext) throws AttributeFilteringException {
        Constraint.isNotNull(attribute, "Attribute to be filtered can not be null");
        Constraint.isNotNull(filterContext, "Attribute filter context can not be null");

        if (null == valuePredicate) {
            //
            // This is a "PolicyRule" rule. So the rule is, if we are true then everything,
            // else nothing.
            //
            if (apply(filterContext)) {
                return attribute.getValues();
            } else {
                return Collections.EMPTY_SET;
            }
        }

        HashSet matchedValues = new HashSet();

        for (AttributeValue value : attribute.getValues()) {
            try {
                if (valuePredicate.apply(value)) {
                    matchedValues.add(value);
                }
            } catch (Exception e) {
                // TODO
                log.debug("Attribute value '{}' of type '{}' caused an error while being evaluated '{}':\n{}",
                        new Object[] {value, value.getClass().getName(), valuePredicate.getClass().getName(), e});
                throw new AttributeFilteringException("Unable to apply predicate to attribute value", e);
            }
        }

        return matchedValues;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (obj == this) {
            return true;
        }

        if (!(obj instanceof BaseValuePredicateMatcher)) {
            return false;
        }

        return Objects.equal(valuePredicate, ((BaseValuePredicateMatcher) obj).valuePredicate);
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return valuePredicate.hashCode();
    }

    /** {@inheritDoc} */
    public String toString() {
        return Objects.toStringHelper(this).add("valuePredicate", valuePredicate).toString();
    }
}