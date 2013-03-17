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

import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.filtering.AttributeFilterContext;

import com.google.common.base.Predicate;
public class TestValuePredicateMatcher extends BaseValuePredicateMatcher {

    final boolean predicateValue;
    
    /**
     * Constructor.
     *
     * @param valueMatchingPredicate
     */
    public TestValuePredicateMatcher(Predicate valueMatchingPredicate) {
        super(valueMatchingPredicate);
        predicateValue = false;
    }
    
    public TestValuePredicateMatcher(boolean value) {
        predicateValue = value;
    }

    /** {@inheritDoc} */
    public boolean apply(@Nullable AttributeFilterContext arg0) {
        return predicateValue;
    }
    
}