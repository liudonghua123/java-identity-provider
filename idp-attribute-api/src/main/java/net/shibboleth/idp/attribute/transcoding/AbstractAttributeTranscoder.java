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

package net.shibboleth.idp.attribute.transcoding;

import java.util.function.Predicate;

import javax.annotation.Nonnull;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;

/**
 * Base class for transcoders.
 * 
 * @param <T> type of object supported
 */
public abstract class AbstractAttributeTranscoder<T> extends AbstractInitializableComponent
        implements AttributeTranscoder<T> {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AbstractAttributeTranscoder.class);

    /** Condition for use of this encoder. */
    @Nonnull private Predicate<ProfileRequestContext> activationCondition;
    
    /** Constructor. */
    public AbstractAttributeTranscoder() {
        activationCondition = Predicates.alwaysTrue();
    }
    
    /** {@inheritDoc} */
    @Nonnull public Predicate<ProfileRequestContext> getActivationCondition() {
        return activationCondition;
    }
    
    /**
     * Set the activation condition for this encoder.
     * 
     * @param condition condition to set
     */
    public void setActivationCondition(@Nonnull final Predicate<ProfileRequestContext> condition) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        activationCondition = Constraint.isNotNull(condition, "Activation condition cannot be null");
    }
    
    /**
     * Checks if the given value can be handled by the transcoder.
     * 
     * <p>In many cases this is simply a check to see if the given object is of the right type.</p>
     * 
     * @param idpAttribute the attribute being encoded, never null
     * @param value the value to check, never null
     * 
     * @return true if the transcoder can encode this value, false if not
     */
    protected abstract boolean canEncodeValue(@Nonnull final IdPAttribute idpAttribute,
            @Nonnull final IdPAttributeValue value);

}