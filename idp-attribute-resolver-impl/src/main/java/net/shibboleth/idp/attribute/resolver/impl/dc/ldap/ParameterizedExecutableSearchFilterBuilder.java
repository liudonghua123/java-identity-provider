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

package net.shibboleth.idp.attribute.resolver.impl.dc.ldap;

import javax.annotation.Nonnull;

import org.ldaptive.SearchFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.resolver.AttributeRecipientContext;
import net.shibboleth.idp.attribute.resolver.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An {@link net.shibboleth.idp.attribute.resolver.impl.dc.ExecutableSearchBuilder} that generates the search
 * filter to be executed by evaluating a parameterized filter string against the currently resolved attributes within a
 * {@link AttributeResolutionContext}.
 */
public class ParameterizedExecutableSearchFilterBuilder extends AbstractExecutableSearchFilterBuilder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ParameterizedExecutableSearchFilterBuilder.class);

    /** LDAP search filter. */
    private final String searchFilter;

    /**
     * Constructor.
     * 
     * @param filter used for the LDAP search
     */
    public ParameterizedExecutableSearchFilterBuilder(@Nonnull final String filter) {
        searchFilter = Constraint.isNotNull(filter, "Search filter can not be null");
    }

    /** {@inheritDoc} */
    public ExecutableSearchFilter build(@Nonnull final AttributeResolutionContext resolutionContext)
            throws ResolutionException {
        final AttributeRecipientContext subContext = resolutionContext.getSubcontext(AttributeRecipientContext.class);
        log.trace("Creating search filter using context {}", subContext);
        final SearchFilter sf = new SearchFilter(searchFilter);
        sf.setParameter("principalName", subContext.getPrincipal());
        return super.build(sf);
    }
}