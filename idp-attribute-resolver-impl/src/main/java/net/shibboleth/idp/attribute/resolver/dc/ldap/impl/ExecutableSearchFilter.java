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

package net.shibboleth.idp.attribute.resolver.dc.ldap.impl;

import javax.annotation.Nonnull;

import org.ldaptive.FilterTemplate;
import org.ldaptive.LdapException;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchResponse;

import net.shibboleth.idp.attribute.resolver.dc.impl.ExecutableSearch;

/** A search filter that can be executed against an LDAP to fetch results. */
public interface ExecutableSearchFilter extends ExecutableSearch {

    /**
     * Performs an LDAP search and returns the results.
     * 
     * @param operation configured to perform searches
     *
     * @return the result of this search filter
     * 
     * @throws LdapException thrown if there is an error performing the search
     */
    @Nonnull SearchResponse execute(@Nonnull SearchOperation operation)
            throws LdapException;

    /**
     * Returns the search filter associated with this executable search filter.
     *
     * @return  search filter
     */
    @Nonnull
    FilterTemplate getFilterTemplate();
}