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

package net.shibboleth.idp.attribute.resolver.spring.enc.impl;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;

import net.shibboleth.idp.attribute.resolver.spring.enc.BaseSAML1AttributeEncoderParser;
import net.shibboleth.idp.attribute.resolver.spring.impl.AttributeResolverNamespaceHandler;
import net.shibboleth.idp.saml.attribute.transcoding.impl.SAML1ByteAttributeTranscoder;

/**
 * Spring Bean Definition Parser for {@link SAML1ByteAttributeTranscoder}.
 */
public class SAML1Base64AttributeEncoderParser extends BaseSAML1AttributeEncoderParser {

    /** Schema type name. */
    @Nonnull public static final QName TYPE_NAME_RESOLVER = new QName(AttributeResolverNamespaceHandler.NAMESPACE, 
            "SAML1Base64");

    /** {@inheritDoc} */
    @Override
    protected BeanDefinition buildTranscoder() {
        return BeanDefinitionBuilder.genericBeanDefinition(SAML1ByteAttributeTranscoder.class).getBeanDefinition();
    }

}