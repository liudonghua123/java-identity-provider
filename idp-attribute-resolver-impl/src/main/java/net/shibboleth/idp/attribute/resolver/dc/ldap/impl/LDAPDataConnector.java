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

import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapException;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchResponse;
import org.ldaptive.ssl.SSLContextInitializer;
import org.ldaptive.ssl.SslConfig;
import org.ldaptive.ssl.X509SSLContextInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.dc.ValidationException;
import net.shibboleth.idp.attribute.resolver.dc.Validator;
import net.shibboleth.idp.attribute.resolver.dc.impl.AbstractSearchDataConnector;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * A {@link net.shibboleth.idp.attribute.resolver.DataConnector} that queries an LDAP in order to retrieve attribute
 * data.
 */
public class LDAPDataConnector extends AbstractSearchDataConnector<ExecutableSearchFilter,SearchResultMappingStrategy> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(LDAPDataConnector.class);

    /** Factory for retrieving LDAP connections. */
    private ConnectionFactory connectionFactory;

    /** For executing LDAP searches. */
    private SearchOperation searchOperation;

    /** Whether the default validator is being used. */
    private boolean defaultValidator = true;

    /** Whether the default mapping strategy is being used. */
    private boolean defaultMappingStrategy = true;

    /**
     * Constructor.
     */
    public LDAPDataConnector() {
    }

    /**
     * Gets the connection factory for retrieving {@link Connection}s.
     * 
     * @return connection factory for retrieving {@link Connection}s
     */
    public ConnectionFactory getConnectionFactory() {
        return connectionFactory;
    }

    /**
     * Sets the connection factory for retrieving {@link Connection}s.
     * 
     * @param factory connection factory for retrieving {@link Connection}s
     */
    public void setConnectionFactory(@Nonnull final ConnectionFactory factory) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        connectionFactory = Constraint.isNotNull(factory, "LDAP connection factory can not be null");
    }

    /**
     * Gets the search operation for executing searches.
     * 
     * @return search operation for executing searches
     */
    public SearchOperation getSearchOperation() {
        return searchOperation;
    }

    /**
     * Sets the search operation for executing searches.
     * 
     * @param operation for executing searches
     */
    public void setSearchOperation(@Nonnull final SearchOperation operation) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        searchOperation = Constraint.isNotNull(operation, "LDAP search operation can not be null");
    }

    /** {@inheritDoc} */
    @Override public void setValidator(@Nonnull final Validator validator) {
        super.setValidator(validator);
        defaultValidator = false;
    }

    /** {@inheritDoc} */
    @Override public void setMappingStrategy(@Nonnull final SearchResultMappingStrategy strategy) {
        super.setMappingStrategy(strategy);
        defaultMappingStrategy = false;
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        if (connectionFactory == null) {
            throw new ComponentInitializationException(getLogPrefix() + " No connection factory was configured");
        }
        if (searchOperation == null) {
            throw new ComponentInitializationException(getLogPrefix() + " No search operation was configured");
        }

        searchOperation.setConnectionFactory(connectionFactory);
        if (defaultValidator) {
            final ConnectionFactoryValidator validator = new ConnectionFactoryValidator();
            validator.setConnectionFactory(connectionFactory);
            super.setValidator(validator);
        }
        getValidator().setThrowValidateError(isFailFastInitialize());
        if (defaultMappingStrategy) {
            super.setMappingStrategy(new StringAttributeValueMappingStrategy());
        }
        super.doInitialize();

        try {
            getValidator().validate();
        } catch (final ValidationException e) {
            log.error("{} Invalid connector configuration", getLogPrefix(), e);
            if (isFailFastInitialize()) {
                // Should always follow this leg.
                throw new ComponentInitializationException(getLogPrefix() + " Invalid connector configuration", e);
            }
        }
        policeForJVMTrust();
    }

// CheckStyle: CyclomaticComplexity OFF
    /** Police SSL for JVM trust.
     * @throws ComponentInitializationException if we detect an SSL issue
     */
    private void policeForJVMTrust() throws ComponentInitializationException {
        try {
            final ConnectionConfig connConfig = connectionFactory.getConnectionConfig();
            if (connConfig.getUseStartTLS() ||
                (connConfig.getLdapUrl() != null && connConfig.getLdapUrl().toLowerCase().contains("ldaps://"))) {
                final SslConfig sslConfig = connConfig.getSslConfig();
                if (sslConfig != null) {
                    final SSLContextInitializer cxtInit = sslConfig.getCredentialConfig() != null ?
                        sslConfig.getCredentialConfig().createSSLContextInitializer() : null;
                    if (cxtInit instanceof X509SSLContextInitializer) {
                        if (((X509SSLContextInitializer) cxtInit).getTrustCertificates() == null) {
                            throw new ComponentInitializationException("Cannot use the default JVM trust store for "+
                                    getLogPrefix());
                        }
                    }
                }
            }
        } catch (final Exception e) {
            log.debug("{} Failed to inspect SSL implementation", getLogPrefix(), e);
        }
    }
 // CheckStyle: CyclomaticComplexity ON

    /**
     * Attempts to retrieve attributes from the LDAP.
     * 
     * @param filter search filter used to retrieve data from the LDAP
     * 
     * @return search result from the LDAP
     * 
     * @throws ResolutionException thrown if there is a problem retrieving data from the LDAP
     */
    @Override @Nullable protected Map<String, IdPAttribute> retrieveAttributes(final ExecutableSearchFilter filter)
            throws ResolutionException {

        if (filter == null) {
            throw new ResolutionException(getLogPrefix() + " Search filter cannot be null");
        }
        try {
            final SearchResponse result = filter.execute(searchOperation);
            log.trace("{} Search returned {}", getLogPrefix(), result);
            return getMappingStrategy().map(result);
        } catch (final LdapException e) {
            throw new ResolutionException(getLogPrefix() + " Unable to execute LDAP search", e);
        }
    }

}