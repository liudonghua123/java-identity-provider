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

package net.shibboleth.idp.attribute.resolver.spring.dc.http.impl;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import net.shibboleth.ext.spring.util.SpringSupport;
import net.shibboleth.idp.attribute.resolver.dc.http.impl.HTTPDataConnector;
import net.shibboleth.idp.attribute.resolver.dc.http.impl.ScriptedResponseMappingStrategy;
import net.shibboleth.idp.attribute.resolver.dc.http.impl.TemplatedURLBuilder;
import net.shibboleth.idp.attribute.resolver.spring.dc.AbstractDataConnectorParser;
import net.shibboleth.idp.attribute.resolver.spring.dc.impl.CacheConfigParser;
import net.shibboleth.idp.attribute.resolver.spring.impl.AttributeResolverNamespaceHandler;
import net.shibboleth.idp.profile.spring.relyingparty.metadata.ScriptTypeBeanParser;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/** Bean definition Parser for a {@link HTTPDataConnector}. */
public class HTTPDataConnectorParser extends AbstractDataConnectorParser {

    /** Schema type name. */
    @Nonnull public static final QName TYPE_NAME =
            new QName(AttributeResolverNamespaceHandler.NAMESPACE, "HTTP");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPDataConnectorParser.class);

    /** {@inheritDoc} */
    @Override protected Class<HTTPDataConnector> getNativeBeanClass() {
        return HTTPDataConnector.class;
    }
    
    /** {@inheritDoc} */
    @Override protected void doV2Parse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {

        log.debug("{} Parsing custom configuration {}", getLogPrefix(), config);

        final V2Parser v2Parser = new V2Parser(config, getLogPrefix());

        final String httpClientID = v2Parser.getBeanHttpClientID();
        if (httpClientID != null) {
            builder.addPropertyReference("httpClient", httpClientID);
        }

        final String searchBuilderID = v2Parser.getBeanSearchBuilderID();
        if (searchBuilderID != null) {
            builder.addPropertyReference("executableSearchBuilder", searchBuilderID);
        } else {
            final BeanDefinition def = v2Parser.createTemplateBuilder();
            if (def != null) {
                builder.addPropertyValue("executableSearchBuilder", def);
            }
        }

        final String mappingStrategyID = v2Parser.getBeanMappingStrategyID();
        if (mappingStrategyID != null) {
            builder.addPropertyReference("mappingStrategy", mappingStrategyID);
        } else {
            final BeanDefinition def = v2Parser.createMappingStrategy(config.getAttributeNS(null, "id"));
            if (def != null) {
                builder.addPropertyValue("mappingStrategy", def);
            }
        }
        
        final String validatorID = v2Parser.getBeanValidatorID();
        if (validatorID != null) {
            builder.addPropertyReference("validator", validatorID);
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

    /**
     * Utility class for parsing v2 schema configuration.
     * 
     */
    protected static class V2Parser {

        /** Base XML element. */
        @Nonnull private final Element configElement;

        /** Class logger. */
        @Nonnull private final Logger log = LoggerFactory.getLogger(V2Parser.class);

        /** Parent parser's log prefix.*/
        @Nonnull @NotEmpty private final String logPrefix;

        /**
         * Creates a new V2Parser with the supplied element.
         * 
         * @param config HTTP DataConnector element
         * @param prefix the parent parser's log prefix.
         */
        public V2Parser(@Nonnull final Element config,  @Nonnull @NotEmpty final String prefix) {
            Constraint.isNotNull(config, "HTTP DataConnector element cannot be null");
            configElement = config;
            logPrefix = prefix;
        }

        /**
         * Get the bean ID of an externally defined HttpClient.
         * 
         * @return HttpClient bean ID
         */
        @Nullable public String getBeanHttpClientID() {
            return AttributeSupport.getAttributeValue(configElement, new QName("httpClientRef"));
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
         * Create the definition of the template driven search builder.
         * 
         * @return the bean definition for the template search builder.
         */
        @Nonnull public BeanDefinition createTemplateBuilder() {
            final BeanDefinitionBuilder templateBuilder =
                    BeanDefinitionBuilder.genericBeanDefinition(TemplatedURLBuilder.class);
            templateBuilder.setInitMethodName("initialize");
            templateBuilder.setDestroyMethodName("destroy");

            String velocityEngineRef = StringSupport.trimOrNull(configElement.getAttributeNS(null, "templateEngine"));
            if (null == velocityEngineRef) {
                velocityEngineRef = "shibboleth.VelocityEngine";
            }
            templateBuilder.addPropertyReference("velocityEngine", velocityEngineRef);

            final String securityParams =
                    StringSupport.trimOrNull(configElement.getAttributeNS(null, "httpClientSecurityParametersRef"));
            if (securityParams != null) {
                templateBuilder.addPropertyReference("httpClientSecurityParameters", securityParams);
            }
            
            final List<Element> urlTemplates = ElementSupport.getChildElements(configElement, 
                            new QName(AttributeResolverNamespaceHandler.NAMESPACE, "URLTemplate"));
            
            if (urlTemplates.size() > 1) {
                log.warn("{} A maximum of 1 <URLTemplate> should be specified; the first one has been used",
                        getLogPrefix());
            }
            
            String url = null;
            if (!urlTemplates.isEmpty()) {
                url = urlTemplates.get(0).getTextContent();
            }
            templateBuilder.addPropertyValue("templateText", url);

            templateBuilder.setInitMethodName("initialize");
            templateBuilder.setDestroyMethodName("destroy");
            return templateBuilder.getBeanDefinition();
        }
        
        /**
         * Get the bean ID of an externally defined mapping strategy.
         * 
         * @return mapping strategy bean ID
         */
        @Nullable public String getBeanMappingStrategyID() {
            return AttributeSupport.getAttributeValue(configElement, null, "mappingStrategyRef");
        }

        /**
         * Create the scripted result mapping strategy.
         * 
         * @param id the ID of the 
         * 
         * @return mapping strategy
         */
        @Nullable public BeanDefinition createMappingStrategy(@Nullable final String id) {

            final List<Element> mappings = ElementSupport.getChildElements(configElement, 
                    new QName(AttributeResolverNamespaceHandler.NAMESPACE, "ResponseMapping"));
    
            if (mappings.size() > 1) {
                log.warn("{} A maximum of 1 <ResponseMapping> should be specified; the first one has been used",
                        getLogPrefix());
            }
            
            final BeanDefinitionBuilder mapper =
                    ScriptTypeBeanParser.parseScriptType(ScriptedResponseMappingStrategy.class, mappings.get(0));
            if (id != null) {
                mapper.addPropertyValue("logPrefix", id + ':');
            }
            
            final String maxLength = StringSupport.trimOrNull(configElement.getAttributeNS(null, "maxLength"));
            if (maxLength != null) {
                mapper.addPropertyValue("maxLength", maxLength);
            }
            
            if (configElement.hasAttributeNS(null, "acceptStatuses")) {
                mapper.addPropertyValue("acceptStatuses",
                        SpringSupport.getAttributeValueAsManagedList(
                                configElement.getAttributeNodeNS(null, "acceptStatuses")));
            }

            if (configElement.hasAttributeNS(null, "acceptTypes")) {
                mapper.addPropertyValue("acceptTypes",
                        SpringSupport.getAttributeValueAsManagedList(
                                configElement.getAttributeNodeNS(null, "acceptTypes")));
            }

            return mapper.getBeanDefinition();
        }
        
        /**
         * Get the bean ID of an externally defined validator.
         * 
         * @return validator bean ID
         */
        @Nullable public String getBeanValidatorID() {
            return AttributeSupport.getAttributeValue(configElement, null, "validatorRef");
        }
        
        /**
         * Create the results cache. See {@link CacheConfigParser}.
         * 
         * @param parserContext bean parser context
         * 
         * @return results cache
         */
        @Nullable public BeanDefinition createCache(@Nonnull final ParserContext parserContext) {
            final CacheConfigParser parser = new CacheConfigParser(configElement);
            return parser.createCache(parserContext);
        }
        
        /** The parent parser's log prefix.
         * @return the log prefix.
         */
        @Nonnull @NotEmpty private String getLogPrefix() {
            return logPrefix;
        }
    }
    
}