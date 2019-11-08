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

package net.shibboleth.idp.attribute.resolver.spring.dc.ldap.impl;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.ldaptive.ActivePassiveConnectionStrategy;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.FilterTemplate;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.RandomConnectionStrategy;
import org.ldaptive.RoundRobinConnectionStrategy;
import org.ldaptive.SearchConnectionValidator;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchScope;
import org.ldaptive.handler.CaseChangeEntryHandler;
import org.ldaptive.handler.CaseChangeEntryHandler.CaseChange;
import org.ldaptive.handler.DnAttributeEntryHandler;
import org.ldaptive.handler.LdapEntryHandler;
import org.ldaptive.pool.IdlePruneStrategy;
import org.ldaptive.pool.PoolConfig;
import org.ldaptive.sasl.Mechanism;
import org.ldaptive.sasl.SaslConfig;
import org.ldaptive.ssl.SslConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import net.shibboleth.ext.spring.util.SpringSupport;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.ConnectionFactoryValidator;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.LDAPDataConnector;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.StringAttributeValueMappingStrategy;
import net.shibboleth.idp.attribute.resolver.dc.ldap.impl.TemplatedExecutableSearchFilterBuilder;
import net.shibboleth.idp.attribute.resolver.spring.dc.AbstractDataConnectorParser;
import net.shibboleth.idp.attribute.resolver.spring.dc.impl.CacheConfigParser;
import net.shibboleth.idp.attribute.resolver.spring.impl.AttributeResolverNamespaceHandler;
import net.shibboleth.idp.profile.spring.factory.BasicX509CredentialFactoryBean;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport.ObjectType;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;
import net.shibboleth.utilities.java.support.xml.XMLConstants;

/**
 * Bean definition Parser for a {@link LDAPDataConnector}. <em>Note</em> That parsing the V2 configuration will set some
 * beans with hard wired defaults. See {@link #doV2Parse(Element, ParserContext, BeanDefinitionBuilder)}.
 */
public class LDAPDataConnectorParser extends AbstractDataConnectorParser {

    /** Schema type - resolver. */
    @Nonnull public static final QName
        TYPE_NAME_RESOLVER = new QName(AttributeResolverNamespaceHandler.NAMESPACE, "LDAPDirectory");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(LDAPDataConnectorParser.class);

    /** {@inheritDoc} */
    @Override protected Class<LDAPDataConnector> getNativeBeanClass() {
        return LDAPDataConnector.class;
    }
    
    // CheckStyle: MethodLength|CyclomaticComplexity OFF
    /**
     * Parses a version 2 configuration. <br/>
     * The following automatically created &amp; injected beans acquire hard wired defaults:
     * <ul>
     * <li>{@link SearchRequest#setTimeLimit(Duration)} defaults to 3s, overridden by the "searchTimeLimit" attribute.
     * </li>
     * <li>{@link SearchRequest#setSizeLimit(int)} defaults to 1, overridden by the "maxResultSize" attribute.</li>
     * <li>{@link SearchRequest#setBaseDn(String)} default to "", overridden by the "validateDN" attribute.</li>
     * <li>{@link SearchFilter#SearchFilter(String)} defaults to "(objectClass=*)", overridden by the "validateFilter"
     * attribute.</li>
     * <li>{@link PoolConfig#setMinPoolSize(int)} defaults to 0 if neither the attribute "poolInitialSize" nor the
     * attribute "minPoolSize" are set.</li>
     * <li>{@link PoolConfig#setMaxPoolSize(int)} defaults to 3 if neither the attribute "poolMaxIdleSize" nor the
     * attribute "maxPoolSize" are set.</li>
     * <li>{@link PoolConfig#setValidatePeriod(Duration)} defaults to 1800, overridden by the attribute
     * "validateTimerPeriod"</li>
     * </ul>
     * 
     * @param config LDAPDirectory containing v2 configuration
     * @param parserContext bean definition parsing context
     * @param builder to initialize
     */
    @Override protected void doV2Parse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {
        log.debug("{} Parsing v2 configuration {}", getLogPrefix(), config);

        final V2Parser v2Parser = new V2Parser(config, getLogPrefix());

        final BeanDefinitionBuilder connectionFactory;
        final Element poolConfigElement = getConnectionPoolElement(config);
        if (poolConfigElement == null) {
            connectionFactory = BeanDefinitionBuilder.genericBeanDefinition(DefaultConnectionFactory.class);
        } else {
            connectionFactory = v2Parser.createPooledConnectionFactory(poolConfigElement);
        }
        connectionFactory.addConstructorArgValue(v2Parser.createConnectionConfig(parserContext));
        builder.addPropertyValue("connectionFactory", connectionFactory.getBeanDefinition());

        final String searchBuilderID = v2Parser.getBeanSearchBuilderID();
        if (searchBuilderID != null) {
            builder.addPropertyReference("executableSearchBuilder", searchBuilderID);
        } else {
            final BeanDefinition def = v2Parser.createTemplateBuilder();
            if (def != null) {
                builder.addPropertyValue("executableSearchBuilder", def);
            }
        }

        final BeanDefinition searchOperation = v2Parser.createSearchOperation();
        builder.addPropertyValue("searchOperation", searchOperation);

        final String mappingStrategyID = AttributeSupport.getAttributeValue(config, new QName("mappingStrategyRef"));
        if (mappingStrategyID != null) {
            builder.addPropertyReference("mappingStrategy", mappingStrategyID);
        } else {
            final BeanDefinition def = v2Parser.createMappingStrategy();
            if (def != null) {
                builder.addPropertyValue("mappingStrategy", def);
            }
        }

        final String validatorID = AttributeSupport.getAttributeValue(config, new QName("validatorRef"));
        if (validatorID != null) {
            builder.addPropertyReference("validator", validatorID);
        } else {
            builder.addPropertyValue("validator", v2Parser.createValidator(connectionFactory.getBeanDefinition()));
        }
        
        final String resultCacheBeanID = CacheConfigParser.getBeanResultCacheID(config);
        if (null != resultCacheBeanID) {
            builder.addPropertyReference("resultsCache", resultCacheBeanID);
        } else {
            builder.addPropertyValue("resultsCache", v2Parser.createCache(parserContext));
        }

        builder.setInitMethodName("initialize");
        builder.setDestroyMethodName("destroy");
    }

    /** Get the Pool configuration &lt;ConnectionPool&gt; element contents, warning if there is more than one.
     * @return the &lt;ConnectionPool&gt; or null if there isn't one.
     */
    @Nullable Element getConnectionPoolElement(final Element element) {
        final List<Element> poolConfigElements =
            ElementSupport.getChildElementsByTagNameNS(element,
                AttributeResolverNamespaceHandler.NAMESPACE, "ConnectionPool");
        if (poolConfigElements.isEmpty()) {
            return null;
        }
        if (poolConfigElements.size() > 1) {
            log.warn("{} Only one <ConnectionPool> should be specified; only the first has been consulted.",
                getLogPrefix());
        }

        return poolConfigElements.get(0);
    }

    // Checkstyle: CyclomaticComplexity|MethodLength ON

    /**
     * Utility class for parsing v2 schema configuration.
     * 
     * <em>Note</em> That parsing the V2 configuration will set some beans with hard wired defaults. See
     * {@link #doV2Parse(Element, ParserContext, BeanDefinitionBuilder)}.
     */

    protected static class V2Parser {

        /** LDAPDirectory XML element. */
        private final Element configElement;

        /** Class logger. */
        private final Logger log = LoggerFactory.getLogger(V2Parser.class);
        
        /** LogPrefix of parent. */
        private final String logPrefix;

        /**
         * Creates a new V2Parser with the supplied LDAPDirectory element.
         * 
         * @param config LDAPDirectory element
         * @param prefix the parent's log prefix
         */
        public V2Parser(@Nonnull final Element config, @Nonnull final String prefix) {
            Constraint.isNotNull(config, "LDAPDirectory element cannot be null");
            configElement = config;
            logPrefix = prefix; 
        }

        /**
         * Creates a connection config bean definition from a v2 XML configuration.
         * 
         * @param parserContext bean definition parsing context
         * @return connection config bean definition
         */
        // CheckStyle: CyclomaticComplexity OFF
        @Nonnull public BeanDefinition createConnectionConfig(@Nonnull final ParserContext parserContext) {
            final String url = AttributeSupport.getAttributeValue(configElement, new QName("ldapURL"));
            final String useStartTLS = AttributeSupport.getAttributeValue(configElement, new QName("useStartTLS"));
            final String principal = AttributeSupport.getAttributeValue(configElement, new QName("principal"));
            final String principalCredential =
                    AttributeSupport.getAttributeValue(configElement, new QName("principalCredential"));
            final String authenticationType =
                    AttributeSupport.getAttributeValue(configElement, new QName("authenticationType"));
            final String connectTimeout =
                    AttributeSupport.getAttributeValue(configElement, new QName("connectTimeout"));
            final String responseTimeout =
                    AttributeSupport.getAttributeValue(configElement, new QName("responseTimeout"));

            final BeanDefinitionBuilder connectionConfig =
                    BeanDefinitionBuilder.genericBeanDefinition(ConnectionConfig.class);
            connectionConfig.addPropertyValue("ldapUrl", url);
            if (useStartTLS != null) {
                connectionConfig.addPropertyValue("useStartTLS", useStartTLS);
            }
            if (connectTimeout != null) {
                connectionConfig.addPropertyValue("connectTimeout", connectTimeout);
            } else {
                connectionConfig.addPropertyValue("connectTimeout", Duration.ofSeconds(3));
            }
            if (responseTimeout != null) {
                connectionConfig.addPropertyValue("responseTimeout", responseTimeout);
            } else {
                connectionConfig.addPropertyValue("responseTimeout", Duration.ofSeconds(3));
            }
            final BeanDefinitionBuilder sslConfig = BeanDefinitionBuilder.genericBeanDefinition(SslConfig.class);
            sslConfig.addPropertyValue("credentialConfig", createCredentialConfig(parserContext));
            connectionConfig.addPropertyValue("sslConfig", sslConfig.getBeanDefinition());
            final BeanDefinitionBuilder connectionInitializer =
                    BeanDefinitionBuilder.genericBeanDefinition(BindConnectionInitializer.class);
            if (principal != null) {
                connectionInitializer.addPropertyValue("bindDn", principal);
            }
            if (principalCredential != null) {
                final BeanDefinitionBuilder credential = BeanDefinitionBuilder.genericBeanDefinition(Credential.class);
                credential.addConstructorArgValue(principalCredential);
                connectionInitializer.addPropertyValue("bindCredential", credential.getBeanDefinition());
            }
            if (authenticationType != null) {
                final Mechanism mechanism = Mechanism.valueOf(authenticationType);
                if (mechanism != null) {
                    final SaslConfig config = new SaslConfig();
                    config.setMechanism(mechanism);
                    connectionInitializer.addPropertyValue("bindSaslConfig", config);
                }
            }
            if (principal != null || principalCredential != null || authenticationType != null) {
                connectionConfig.addPropertyValue("connectionInitializers", connectionInitializer.getBeanDefinition());
            }
            final String connectionStrategy = AttributeSupport.getAttributeValue(
                configElement, new QName("connectionStrategy"));
            if (connectionStrategy == null) {
                connectionConfig.addPropertyValue("connectionStrategy", new ActivePassiveConnectionStrategy());
            } else {
                switch (connectionStrategy) {
                case "ROUND_ROBIN":
                    connectionConfig.addPropertyValue("connectionStrategy", new RoundRobinConnectionStrategy());
                    break;

                case "RANDOM":
                    connectionConfig.addPropertyValue("connectionStrategy", new RandomConnectionStrategy());
                    break;

                default:
                    connectionConfig.addPropertyValue("connectionStrategy", new ActivePassiveConnectionStrategy());
                    break;
                }
            }

            return connectionConfig.getBeanDefinition();
        }
        // CheckStyle: CyclomaticComplexity ON

        /**
         * Read StartTLS trust and authentication credentials.
         * 
         * @param parserContext bean definition parsing context
         * @return credential config
         */
        @Nonnull protected BeanDefinition createCredentialConfig(@Nonnull final ParserContext parserContext) {
            final BeanDefinitionBuilder result =
                    BeanDefinitionBuilder.genericBeanDefinition(CredentialConfigFactoryBean.class);

            final List<Element> trustElements =
                    ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE,
                            "StartTLSTrustCredential");
            final String trustResource =
                    StringSupport.trimOrNull(AttributeSupport.getAttributeValue(configElement, null, "trustFile"));
            if (trustResource != null) {
                if (!trustElements.isEmpty()) {
                    log.warn("{} StartTLSTrustCredential and trustFile= are incompatible.  trustFile used.",
                            getLogPrefix());
                }
                final BeanDefinitionBuilder credential =
                        BeanDefinitionBuilder.genericBeanDefinition(BasicX509CredentialFactoryBean.class);
                credential.addPropertyValue("certificateResource", trustResource);
                result.addPropertyValue("trustCredential", credential.getBeanDefinition());
            } else if (!trustElements.isEmpty()) {
                if (trustElements.size() > 1) {
                    log.warn("{} Too many StartTLSTrustCredential elements in {}; only the first has been consulted",
                            getLogPrefix(), parserContext.getReaderContext().getResource().getDescription());
                }
                result.addPropertyValue("trustCredential",
                        SpringSupport.parseCustomElement(trustElements.get(0), parserContext, result, false));
            }

            final List<Element> authElements =
                    ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE, "StartTLSAuthenticationCredential");
            final String authKey =
                    StringSupport.trimOrNull(AttributeSupport.getAttributeValue(configElement, null, "authKey"));
            final String authCert =
                    StringSupport.trimOrNull(AttributeSupport.getAttributeValue(configElement, null, "authCert"));

            if (authKey != null|| authCert != null) {

                if (!authElements.isEmpty()) {
                    log.warn("{} StartTLSAuthenticationCredential and"
                            + " authKey/authCert= are incompatible.  authCert/authKey used.",
                            getLogPrefix());
                }
                final BeanDefinitionBuilder authCred =
                        BeanDefinitionBuilder.genericBeanDefinition(BasicX509CredentialFactoryBean.class);
                authCred.addPropertyValue("certificateResource", authCert);
                authCred.addPropertyValue("privateKeyResource", authKey);
                authCred.addPropertyValue("privateKeyPassword",
                                           AttributeSupport.getAttributeValue(configElement, null, "authKeyPassword"));


                result.addPropertyValue("authCredential", authCred.getBeanDefinition());

            } else if (!authElements.isEmpty()) {
                if (authElements.size() > 1) {
                    log.warn("{} Too many StartTLSAuthenticationCredential elements in {};"
                            + " only the first has been consulted", getLogPrefix(), 
                            parserContext.getReaderContext().getResource().getDescription());
                }
                result.addPropertyValue("authCredential", SpringSupport
                        .parseCustomElement(authElements.get(0), parserContext, result, false));
            }

            return result.getBeanDefinition();
        }
        
        /**
         * Get the textual content of the &lt;FilterTemplate&gt;.
         * 
         * We have to look in two places and warn appropriately.
         * @return the filter or null.
         */
        @Nullable private String getFilterText() {
            final List<Element> filterElements = ElementSupport.getChildElementsByTagNameNS(configElement,
                    AttributeResolverNamespaceHandler.NAMESPACE, "FilterTemplate");
            
            final String filter;
            if (!filterElements.isEmpty()) {
                if (filterElements.size() > 1) {
                    log.warn("{} only one <FilterTemplate> can be specified; only the first has been consulted",
                            getLogPrefix());
                }
                filter = StringSupport.trimOrNull(filterElements.get(0).getTextContent().trim());
            } else {
                filter = null;
            }
            return filter;
        }

        /**
         * Get the bean ID of an externally defined search builder.
         * 
         * @return search builder bean ID
         */
        @Nullable public String getBeanSearchBuilderID() {
            return AttributeSupport.getAttributeValue(configElement, null, "executableSearchBuilderRef");
        }
        
        /**
         * Construct the definition of the template driven search builder.
         * 
         * @return the bean definition for the template search builder.
         */
        @Nonnull public BeanDefinition createTemplateBuilder() {
            final BeanDefinitionBuilder templateBuilder =
                    BeanDefinitionBuilder.genericBeanDefinition(TemplatedExecutableSearchFilterBuilder.class);
            templateBuilder.setInitMethodName("initialize");

            String velocityEngineRef = StringSupport.trimOrNull(configElement.getAttribute("templateEngine"));
            if (null == velocityEngineRef) {
                velocityEngineRef = "shibboleth.VelocityEngine";
            }
            templateBuilder.addPropertyReference("velocityEngine", velocityEngineRef);

            templateBuilder.addPropertyValue("v2Compatibility", true);

            templateBuilder.addPropertyValue("templateText", getFilterText());

            return templateBuilder.getBeanDefinition();
        }

        /**
         * Creates a new search executor bean definition from a v2 XML configuration.
         *
         * @return search executor bean definition
         */
        // CheckStyle: CyclomaticComplexity|MethodLength OFF
        @Nonnull public BeanDefinition createSearchOperation() {
            final String baseDn = AttributeSupport.getAttributeValue(configElement, new QName("baseDN"));
            final String searchScope = AttributeSupport.getAttributeValue(configElement, new QName("searchScope"));
            final String derefAliases = AttributeSupport.getAttributeValue(configElement, new QName("derefAliases"));
            final String searchTimeLimit =
                    AttributeSupport.getAttributeValue(configElement, new QName("searchTimeLimit"));
            final String maxResultSize = AttributeSupport.getAttributeValue(configElement, new QName("maxResultSize"));
            final String lowercaseAttributeNames =
                    AttributeSupport.getAttributeValue(configElement, new QName("lowercaseAttributeNames"));

            final BeanDefinitionBuilder searchRequest =
                BeanDefinitionBuilder.genericBeanDefinition(SearchRequest.class);
            if (baseDn != null) {
                searchRequest.addPropertyValue("baseDn", baseDn);
            }
            if (searchScope != null) {
                searchRequest.addPropertyValue("searchScope", searchScope);
            }
            if (derefAliases != null) {
                searchRequest.addPropertyValue("derefAliases", derefAliases);
            }
            if (searchTimeLimit != null) {
                searchRequest.addPropertyValue("timeLimit", searchTimeLimit);
            } else {
                searchRequest.addPropertyValue("timeLimit", Duration.ofSeconds(3));
            }
            if (maxResultSize != null) {
                searchRequest.addPropertyValue("sizeLimit", maxResultSize);
            } else {
                searchRequest.addPropertyValue("sizeLimit", 1);
            }

            final List<Element> returnAttrsElements = ElementSupport.getChildElementsByTagNameNS(configElement,
                    AttributeResolverNamespaceHandler.NAMESPACE, "ReturnAttributes");
            if (!returnAttrsElements.isEmpty()) {
                if (returnAttrsElements.size() > 1) {
                    log.warn("{} Only one <ReturnAttributes> element can be specified; "+
                            "only the first has been consulted.", getLogPrefix());
                }
                final Element returnAttrsElement = returnAttrsElements.get(0);
                
                final BeanDefinitionBuilder returnAttrs =
                        BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildStringList");
                returnAttrs.addConstructorArgValue(ElementSupport.getElementContentAsString(returnAttrsElement));
                searchRequest.addPropertyValue("returnAttributes", returnAttrs.getBeanDefinition());
            }

            final List<Element> binaryAttrsElements = ElementSupport.getChildElementsByTagNameNS(configElement,
              AttributeResolverNamespaceHandler.NAMESPACE, "BinaryAttributes");
            if (!binaryAttrsElements.isEmpty()) {
                if (binaryAttrsElements.size() > 1) {
                    log.warn("{} Only one <BinaryAttributes> element can be specified; "+
                      "only the first has been consulted.", getLogPrefix());
                }
                final Element binaryAttrsElement = binaryAttrsElements.get(0);

                final BeanDefinitionBuilder binaryAttrs =
                  BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildStringList");
                binaryAttrs.addConstructorArgValue(ElementSupport.getElementContentAsString(binaryAttrsElement));
                searchRequest.addPropertyValue("binaryAttributes", binaryAttrs.getBeanDefinition());
            }

            final BeanDefinitionBuilder searchOperation =
                BeanDefinitionBuilder.genericBeanDefinition(SearchOperation.class);
            searchOperation.addPropertyValue("request", searchRequest.getBeanDefinition());
            final BeanDefinitionBuilder handlers =
                BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildEntryHandlers");
            handlers.addConstructorArgValue(lowercaseAttributeNames);
            searchOperation.addPropertyValue("entryHandlers", handlers.getBeanDefinition());

            return searchOperation.getBeanDefinition();
        }
        // CheckStyle: CyclomaticComplexity|MethodLength ON
        // CheckStyle: CyclomaticComplexity ON

        /**
         * Initializes the supplied connectionFactory with configuration from the supplied config element.
         *
         * @param  poolConfigElement to parse configuration from
         *
         * @return pooled connection factory bean definition builder
         */
        // CheckStyle: MethodLength OFF
        public BeanDefinitionBuilder createPooledConnectionFactory(final Element poolConfigElement) {

            final BeanDefinitionBuilder connectionFactory = BeanDefinitionBuilder.genericBeanDefinition(
                PooledConnectionFactory.class);
            connectionFactory.addPropertyValue("name", "resolver-pool");

            final String blockWaitTime =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("blockWaitTime"));
            final String expirationTime =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("expirationTime"));

            if (blockWaitTime != null) {
                connectionFactory.addPropertyValue("blockWaitTime", blockWaitTime);
            } else {
                connectionFactory.addPropertyValue("blockWaitTime", Duration.ZERO);
            }
            if (expirationTime != null) {
                final BeanDefinitionBuilder strategy =
                        BeanDefinitionBuilder.genericBeanDefinition(IdlePruneStrategy.class);
                strategy.addConstructorArgValue(expirationTime);
                connectionFactory.addPropertyValue("pruneStrategy", strategy.getBeanDefinition());
            }
            connectionFactory.addPropertyValue("poolConfig", createPoolConfig(poolConfigElement));

            final BeanDefinitionBuilder validator =
                    BeanDefinitionBuilder.rootBeanDefinition(V2Parser.class, "buildSearchValidator");
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validatePeriodically")));
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validateDN")));
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validateFilter")));
            validator.addConstructorArgValue(
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validateTimerPeriod")));
            connectionFactory.addPropertyValue("validator", validator.getBeanDefinition());

            final String failFastInitialize =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("failFastInitialize"));
            if (failFastInitialize != null) {
                // V4 Deprecations
                DeprecationSupport.warnOnce(ObjectType.ATTRIBUTE, "failfastInitialize (on a ConnectionPool element)", 
                        null, "failfastInitialize (on a DataConnector)");
                connectionFactory.addPropertyValue("failFastInitialize", failFastInitialize);
            }
            connectionFactory.setInitMethodName("initialize");
            return connectionFactory;
        }

        // CheckStyle: MethodLength ON

        /**
         * Creates a new pool config bean definition from a v2 XML configuration.
         *
         * @param  poolConfigElement to parse configuration from
         *
         * @return pool config bean definition
         */
        @Nullable protected BeanDefinition createPoolConfig(final Element poolConfigElement) {
            final String minPoolSize = AttributeSupport.getAttributeValue(poolConfigElement, new QName("minPoolSize"));
            final String maxPoolSize = AttributeSupport.getAttributeValue(poolConfigElement, new QName("maxPoolSize"));
            final String validatePeriodically =
                    AttributeSupport.getAttributeValue(poolConfigElement, new QName("validatePeriodically"));

            final BeanDefinitionBuilder poolConfig = BeanDefinitionBuilder.genericBeanDefinition(PoolConfig.class);
            if (minPoolSize == null) {
                poolConfig.addPropertyValue("minPoolSize", 0);
            } else {
                poolConfig.addPropertyValue("minPoolSize", minPoolSize);
            }
            if (maxPoolSize == null) {
                poolConfig.addPropertyValue("maxPoolSize", 3);
            } else {
                poolConfig.addPropertyValue("maxPoolSize", maxPoolSize);
            }
            if (validatePeriodically != null) {
                poolConfig.addPropertyValue("validatePeriodically", validatePeriodically);
            }
            return poolConfig.getBeanDefinition();
        }

        /**
         * Create the result mapping strategy. See {@link net.shibboleth.idp.attribute.resolver.dc.MappingStrategy}.
         * 
         * @return mapping strategy
         */
        @Nullable public BeanDefinition createMappingStrategy() {

            final BeanDefinitionBuilder mapper =
                    BeanDefinitionBuilder.genericBeanDefinition(StringAttributeValueMappingStrategy.class);
            final List<Element> columns = ElementSupport.getChildElementsByTagNameNS(configElement,
                            AttributeResolverNamespaceHandler.NAMESPACE, "Column");

            if (!columns.isEmpty()) {
                final ManagedMap<String, String> renamingMap = new ManagedMap<>();
                for (final Element column : columns) {
                    final String columnName = AttributeSupport.getAttributeValue(column, null, "columnName");
                    final String attributeId = AttributeSupport.getAttributeValue(column, null, "attributeID");
                    if (columnName != null && attributeId != null) {
                        renamingMap.put(columnName, attributeId);
                    }
                }
                mapper.addPropertyValue("resultRenamingMap", renamingMap);
            }

            final String noResultIsError =
                    AttributeSupport.getAttributeValue(configElement, new QName("noResultIsError"));
            if (noResultIsError != null) {
                mapper.addPropertyValue("noResultAnError", SpringSupport.getStringValueAsBoolean(noResultIsError));
            }

            final String multipleResultsIsError =
                    AttributeSupport.getAttributeValue(configElement, new QName("multipleResultsIsError"));
            if (multipleResultsIsError != null) {
                mapper.addPropertyValue("multipleResultsAnError", multipleResultsIsError);
            }
            return mapper.getBeanDefinition();
        }

        /**
         * Create the validator. See {@link net.shibboleth.idp.attribute.resolver.dc.Validator}.
         * 
         * @param connectionFactory to provide to the validator
         * 
         * @return validator
         */
        @Nullable public BeanDefinition createValidator(final BeanDefinition connectionFactory) {

            final BeanDefinitionBuilder validator =
                    BeanDefinitionBuilder.genericBeanDefinition(ConnectionFactoryValidator.class);

            validator.addPropertyValue("connectionFactory", connectionFactory);
            return validator.getBeanDefinition();
        }

        /**
         * Create a results cache bean definition. See {@link CacheConfigParser}.
         * 
         * @param parserContext bean parser context
         * 
         * @return results cache bean definition
         */
        @Nullable public BeanDefinition createCache(@Nonnull final ParserContext parserContext) {
            final CacheConfigParser parser = new CacheConfigParser(configElement);
            return parser.createCache(parserContext);
        }
        
        /** The parent's log prefix.
         * @return the log prefix.  Set up in the constructor.
         */
        @Nonnull String getLogPrefix() {
            return logPrefix;
        }

        /**
         * Converts the supplied value to a list of strings delimited by {@link XMLConstants#LIST_DELIMITERS} and comma.
         * 
         * @param value to convert to a list
         * 
         * @return list of strings
         */
        @Nonnull public static List<String> buildStringList(final String value) {
            return StringSupport.stringToList(value, XMLConstants.LIST_DELIMITERS + ",");
        }

        /**
         * Returns a search validator or null if validatePeriodically is false.
         *
         * @param validatePeriodically whether to create a search validator
         * @param validateDN baseDN to search on
         * @param validateFilter to search with
         * @param validatePeriod on which to search
         *
         * @return  search validator or null
         */
        @Nullable public static SearchConnectionValidator buildSearchValidator(
            @Nullable final String validatePeriodically,
            @Nullable final String validateDN,
            @Nullable final String validateFilter,
            @Nullable final String validatePeriod)
        {
            if (!Boolean.valueOf(validatePeriodically)) {
                return null;
            }
            final SearchRequest searchRequest = new SearchRequest();
            searchRequest.setReturnAttributes("1.1");
            searchRequest.setSearchScope(SearchScope.OBJECT);
            searchRequest.setSizeLimit(1);
            if (validateDN != null) {
                searchRequest.setBaseDn(validateDN);
            } else {
                searchRequest.setBaseDn("");
            }
            final FilterTemplate template = new FilterTemplate();
            if (validateFilter != null) {
                template.setFilter(validateFilter);
            } else {
                template.setFilter("(objectClass=*)");
            }
            searchRequest.setFilter(template);
            final SearchConnectionValidator validator = new SearchConnectionValidator();
            validator.setSearchRequest(searchRequest);
            if (validatePeriod != null) {
                validator.setValidatePeriod(Duration.parse(validatePeriod));
            } else {
                validator.setValidatePeriod(Duration.ofMinutes(30));
            }
            return validator;
        }

        /**
         * Factory method for handling spring property replacement. Adds a {@link DnAttributeEntryHandler} by default.
         * Adds a {@link CaseChangeEntryHandler} if lowercaseAttributeNames is true. 
         * 
         * @param lowercaseAttributeNames boolean string value
         * @return list of ldap entry handlers
         */
        @Nonnull public static List<LdapEntryHandler> buildEntryHandlers(
                @Nullable final String lowercaseAttributeNames) {
            final List<LdapEntryHandler> handlers = new ArrayList<>();
            handlers.add(new DnAttributeEntryHandler());
            if (Boolean.valueOf(lowercaseAttributeNames)) {
                final CaseChangeEntryHandler entryHandler = new CaseChangeEntryHandler();
                entryHandler.setAttributeNameCaseChange(CaseChange.LOWER);
                handlers.add(entryHandler);
            }
            return handlers;
        }
    }

}