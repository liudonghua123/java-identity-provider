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

import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;

import net.shibboleth.ext.spring.service.AbstractServiceableComponent;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoder;
import net.shibboleth.idp.attribute.transcoding.AttributeTranscoderRegistry;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;

/** Service implementation of the {@link AttributeTranscoderRegistry} interface. */
@ThreadSafe
public class AttributeTranscoderRegistryImpl extends AbstractServiceableComponent<AttributeTranscoderRegistry>
        implements AttributeTranscoderRegistry {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AttributeTranscoderRegistryImpl.class);
    
    /** Registry of transcoding instructions for a given "name" and type of object. */
    @Nonnull private final Map<String,Multimap<Class<?>,Properties>> transcodingRegistry;
    
    /** Registry of naming functions for supported object types. */
    @Nonnull private final Map<Class<?>,Function<?,String>> namingFunctionRegistry;
    
    /** Maps acceptable subtypes of a given class into the proper base class to use during registry fuctions. */
    @Nonnull private final Map<Class<?>,Class<?>> classEquivalenceRegistry;

    /** Constructor. */
    public AttributeTranscoderRegistryImpl() {
        transcodingRegistry = new HashMap<>();
        namingFunctionRegistry = new HashMap<>();
        classEquivalenceRegistry = new HashMap<>();
    }
    
    /** {@inheritDoc} */
    @Override @Nonnull public AttributeTranscoderRegistry getComponent() {
        return this;
    }

    /**
     * Installs registry of naming functions mapped against the types of objects they support.
     * 
     * @param registry map of types to naming functions
     */
    public void setNamingRegistry(@Nonnull @NonnullElements final Map<Class<?>,Function<?,String>> registry) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (registry == null) {
            namingFunctionRegistry.clear();
            return;
        }
        
        registry.forEach((k,v) -> {
            if (k != null && v != null) {
                namingFunctionRegistry.put(k, v);
            }
        });
    }
    
    /**
     * Installs registry of mappings from subclasses of the "officially" registered types to their proper
     * official type so that the registry can ignore them.
     * 
     * <p>For example, if a transcoder registry for type Foo also handles subtypes of Foo, those subtypes
     * should be registered with mappings to Foo.</p>
     * 
     * @param registry mappings from subclass to the canonical parent class
     */
    public void setClassEquivalenceRegistry(@Nonnull @NonnullElements final Map<Class<?>,Class<?>> registry) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (registry == null) {
            classEquivalenceRegistry.clear();
            return;
        }
        
        registry.forEach((k,v) -> {
            if (k != null && v != null && v.isAssignableFrom(k)) {
                classEquivalenceRegistry.put(k, v);
            }
        });
    }

    /**
     * Installs the transcoder mappings en masse.
     * 
     * <p>Each map entry connects an {@link IdPAttribute} name to the rules for transcoding to/from it.</p>
     * 
     * @param registry mappings from internal name to transcoding rules
     */
    public void setTranscoderRegistry(@Nonnull @NonnullElements final Map<String,Collection<Properties>> registry) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (registry == null) {
            transcodingRegistry.clear();
            return;
        }
        
        for (final Map.Entry<String,Collection<Properties>> entry : registry.entrySet()) {
            
            final String internalId = StringSupport.trimOrNull(entry.getKey());
            if (internalId != null && entry.getValue() != null && !entry.getValue().isEmpty()) {

                for (final Properties props : Collections2.filter(entry.getValue(), Predicates.notNull())) {
                    addMapping(internalId, props);
                }
            }
        }
    }
    
    /** {@inheritDoc} */
    @Nonnull @NonnullElements @Unmodifiable public Collection<Properties> getTranscodingProperties(
            @Nonnull final IdPAttribute from, @Nonnull final Class<?> to) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        Constraint.isNotNull(from, "IdPAttribute cannot be null");
        Constraint.isNotNull(to, "Target type cannot be null");
        
        final Multimap<Class<?>,Properties> propertyCollections = transcodingRegistry.get(from.getId());
        
        return propertyCollections != null ? ImmutableList.copyOf(propertyCollections.get(getEffectiveType(to)))
                : Collections.emptyList();
    }

    /** {@inheritDoc} */
    @Nonnull @NonnullElements @Unmodifiable public <T> Collection<Properties> getTranscodingProperties(
            @Nonnull final T from) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        Constraint.isNotNull(from, "Input object cannot be null");
        
        final Class<?> effectiveType = getEffectiveType(from.getClass());
        
        final Function<?,String> namingFunction = namingFunctionRegistry.get(from.getClass());
        if (namingFunction != null) {
            // Don't know if we can work around this cast or not.
            final String id = ((Function<? super T,String>) namingFunction).apply(from);
            if (id != null) {
                final Multimap<Class<?>,Properties> propertyCollections = transcodingRegistry.get(id);
                
                return propertyCollections != null ? ImmutableList.copyOf(propertyCollections.get(effectiveType))
                        : Collections.emptyList();
            } else {
                log.warn("Object of type {} did not have a canonical name", from.getClass().getName());
            }
        } else {
            log.warn("Unsupported object type: {}", from.getClass().getName());
        }
        
        return Collections.emptyList();
    }
    
    /**
     * Add a mapping between an {@link IdPAttribute} name and a set of transcoding rules.
     * 
     * <p>The rules MUST contain at least:</p>
     * <ul>
     *  <li>{@link #PROP_TYPE} - a source/target class for the transcoding rules</li>
     *  <li>{@link #PROP_TRANSCODER} - an {@link AttributeTranscoder} instance supporting the type</li>
     * </ul>
     * 
     * @param id name of the {@link IdPAttribute} to map to/from
     * @param ruleset transcoding rules
     */
    private void addMapping(@Nonnull @NotEmpty final String id, @Nonnull final Properties ruleset) {

        Object transcoder = ruleset.get(PROP_TRANSCODER);
        if (transcoder instanceof String) {
            try {
                transcoder = Class.forName((String) transcoder).getDeclaredConstructor().newInstance();
            } catch (final InstantiationException | IllegalAccessException | IllegalArgumentException
                    | InvocationTargetException | NoSuchMethodException | SecurityException
                    | ClassNotFoundException e) {
                log.warn("Unable to create AttributeTranscoder of specified type {} in transcoding rule for {}",
                        transcoder, id, e);
                return;
            }
        } else if (!(transcoder instanceof AttributeTranscoder)) {
            log.warn("Transcoding rule for {} missing {} property", id, PROP_TRANSCODER);
        }

        final Class<?> type = ((AttributeTranscoder) transcoder).getEncodedType();
        final String targetName = ((AttributeTranscoder) transcoder).getEncodedName(ruleset);
        if (targetName != null) {

            final Properties copy = new Properties();
            copy.putAll(ruleset);

            copy.put(PROP_TRANSCODER, transcoder);
            
            // Install mapping back to IdPAttribute's name.
            copy.setProperty(PROP_ID, id);
            
            Multimap<Class<?>,Properties> rulesetsForIdPName = transcodingRegistry.get(id);
            if (rulesetsForIdPName == null) {
                rulesetsForIdPName = ArrayListMultimap.create();
                transcodingRegistry.put(id, rulesetsForIdPName);
            }
            
            rulesetsForIdPName.put(type, copy);

            Multimap<Class<?>,Properties> rulesetsForEncodedName = transcodingRegistry.get(targetName);
            if (rulesetsForEncodedName == null) {
                rulesetsForEncodedName = ArrayListMultimap.create();
                transcodingRegistry.put(targetName, rulesetsForEncodedName);
            }
            
            rulesetsForEncodedName.put(type, copy);
            
        } else {
            log.warn("Transcoding rule for {} into type {} did not produce an encoded name", id, type.getName());
        }
    }

    /**
     * Convert an input type into the appropriate type (possibly itself) to use in looking up
     * rules in the registry.
     * 
     * @param inputType the type passed into the registry operation
     * 
     * @return the appropriate type to use subsequently
     */
    @Nonnull private Class<?> getEffectiveType(@Nonnull final Class<?> inputType) {
        
        final Class<?> outputType = classEquivalenceRegistry.get(inputType);
        return outputType != null ? outputType : inputType;
    }
    
}