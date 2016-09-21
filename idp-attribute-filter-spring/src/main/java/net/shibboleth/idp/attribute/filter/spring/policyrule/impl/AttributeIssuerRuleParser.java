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

package net.shibboleth.idp.attribute.filter.spring.policyrule.impl;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import net.shibboleth.idp.attribute.filter.policyrule.filtercontext.impl.AttributeIssuerPolicyRule;
import net.shibboleth.idp.attribute.filter.spring.basic.impl.AttributeFilterBasicNamespaceHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bean definition parser for {@link AttributeIssuerPolicyRule}.
 */
public class AttributeIssuerRuleParser extends AbstractStringPolicyRuleParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(AttributeFilterBasicNamespaceHandler.NAMESPACE,
            "AttributeIssuerString");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AttributeIssuerRuleParser.class);

    /** {@inheritDoc} */
    @Override @Nonnull protected Class<AttributeIssuerPolicyRule> getNativeBeanClass() {
        log.warn("The {} element is deprecated and will be removed in future versions", SCHEMA_TYPE);
        return AttributeIssuerPolicyRule.class;
    }

    /** {@inheritDoc} */
    @Override protected QName getAFPName() {
        return SCHEMA_TYPE;
    }

}
