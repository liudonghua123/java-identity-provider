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

package net.shibboleth.idp.attribute.transcoding.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;

import net.shibboleth.ext.spring.service.AbstractServiceableComponent;
import net.shibboleth.idp.attribute.AttributeDecoder;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.collection.ClassToInstanceMultiMap;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Service implementation of the {@link AttributeTranscoderRegistry} interface. */
@ThreadSafe
public class AttributeTranscoderRegistryImpl extends AbstractServiceableComponent<AttributeTranscoderRegistry>
        implements AttributeTranscoderRegistry {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AttributeTranscoderRegistryImpl.class);
    
    /** Registry of encoders for a given attribute ID and type of encoder. */
    @Nonnull private final Map<String,ClassToInstanceMultiMap<AttributeEncoder>> attributeEncoders;

    /** Registry of decoders for a given object "name" and type of decoder. */
    @Nonnull private final Map<String,ClassToInstanceMultiMap<AttributeDecoder>> attributeDecoders;
    
    /** Registry of transcoder types and naming for supported object types. */
    @Nonnull private final Map<Class<?>,TypeInfo> typeInfoRegistry;

    /**
     * Constructor.
     * 
     * @param id ID of this service
     */
    public AttributeTranscoderRegistryImpl(@Nonnull @NotEmpty final String id) {
        setId(id);
        attributeEncoders = new HashMap<>();
        attributeDecoders = new HashMap<>();
        typeInfoRegistry = new HashMap<>();
    }
    
    /** {@inheritDoc} */
    @Override @Nonnull public AttributeTranscoderRegistry getComponent() {
        return this;
    }

    public void setTypeRegistry(@Nonnull @NonnullElements Map<Class<?>,TypeInfo<?>> registry) {
        
    }

    public void setTranscoderRegistry(@Nonnull @NonnullElements Map<String,Collection<?>> registry) {
        
    }
    
    /** {@inheritDoc} */
    @Nonnull @NonnullElements @Unmodifiable
    public <T> Collection<AttributeEncoder<T>> getEncoders(@Nonnull final IdPAttribute from,
            @Nonnull final Class<T> to) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        
        final TypeInfo<T> typeInfo = typeInfoRegistry.get(to);
        if (typeInfo == null) {
            log.warn("Unsupported object type: {}", to.getName());
            return Collections.emptyList();
        }
        
        final ClassToInstanceMultiMap<AttributeEncoder> encoders = attributeEncoders.get(from.getId());
                
        return encoders != null ? encoders.get(typeInfo.getEncoderType()) : Collections.emptyList();
    }

    /** {@inheritDoc} */
    @Nonnull @NonnullElements @Unmodifiable
    public <T> Collection<AttributeDecoder<T>> getDecoders(@Nonnull final T from) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        
        final TypeInfo<T> typeInfo = typeInfoRegistry.get(from.getClass());
        if (typeInfo == null) {
            log.warn("Unsupported object type: {}", from.getClass().getName());
            return Collections.emptyList();
        }
        
        final String id = StringSupport.trimOrNull(typeInfo.getNamingFunction().apply(from));
        if (id == null) {
            log.warn("Object of type {} did not have a canonical name", from.getClass().getName());
            return Collections.emptyList();
        }
        
        final ClassToInstanceMultiMap<AttributeDecoder> decoders = attributeDecoders.get(id);
        
        return decoders != null ? decoders.get(typeInfo.getDecoderType()) : Collections.emptyList();
    }

    /**
     * Metadata connecting data types to naming functions and codec types.
     * 
     * @param <T> object type
     */
    public static class TypeInfo<T> {
        
        /** Function to derive a canonical name. */
        @Nonnull private final Function<T,String> namingFunction;
        
        /** Type of encoder. */
        @Nonnull private final Class<AttributeEncoder<T>> encoderType;
        
        /** Type of decoder. */
        @Nonnull private final Class<AttributeDecoder<T>> decoderType;
        
        /**
         * Constructor.
         *
         * @param naming canonical naming function
         * @param encoder encoder type
         * @param decoder decoder type
         */
        public TypeInfo(@Nonnull @ParameterName(name="naming") final Function<T,String> naming,
                @Nonnull @ParameterName(name="encoder") final Class<AttributeEncoder<T>> encoder,
                @Nonnull @ParameterName(name="decoder") final Class<AttributeDecoder<T>> decoder) {
            
            namingFunction = Constraint.isNotNull(naming, "Naming function cannot be null");
            encoderType = Constraint.isNotNull(encoder, "Encoder type cannot be null");
            decoderType = Constraint.isNotNull(decoder, "Decoder type cannot be null");
        }
        
        /**
         * Gets the function deriving a canonical name for an object.
         * 
         * @return function deriving a canonical name for an object
         */
        @Nonnull public Function<T,String> getNamingFunction() {
            return namingFunction;
        }

        /**
         * Gets the type of encoder supporting an object.
         * 
         * @return type of encoder supporting an object
         */
        @Nonnull public Class<AttributeEncoder<T>> getEncoderType() {
            return encoderType;
        }

        /**
         * Gets the type of decoder supporting an object.
         * 
         * @return type of decoder supporting an object
         */
        @Nonnull public Class<AttributeDecoder<T>> getDecoderType() {
            return decoderType;
        }
    }

}