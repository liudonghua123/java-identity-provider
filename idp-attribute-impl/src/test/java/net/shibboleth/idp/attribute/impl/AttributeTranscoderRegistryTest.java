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

package net.shibboleth.idp.attribute.impl;

import java.util.Collection;

import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.AttributeDecoder;
import net.shibboleth.idp.attribute.AttributeDecodingException;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.idp.attribute.transcoding.impl.AttributeTranscoderRegistryImpl;

/**
 * Test for {@link AttributeTranscoderRegistry}.
 */
public class AttributeTranscoderRegistryTest {


    @Test void testEncode() throws AttributeEncodingException {
        
        final AttributeTranscoderRegistry registry = new AttributeTranscoderRegistryImpl("test");
        
        final IdPAttribute foo = new IdPAttribute("foo");
        
        final Collection<AttributeEncoder<String>> encoders = registry.getEncoders(foo, String.class);
        
        final String s = encoders.iterator().next().encode(foo);
    }
   
    @Test void testDecode() throws AttributeDecodingException {
        
        final AttributeTranscoderRegistry registry = new AttributeTranscoderRegistryImpl("test");
        
        final String foo = new String("foo");
        
        final Collection<AttributeDecoder<String>> decoders = registry.getDecoders(foo);
        
        final IdPAttribute a = decoders.iterator().next().decode(foo);
    }
}