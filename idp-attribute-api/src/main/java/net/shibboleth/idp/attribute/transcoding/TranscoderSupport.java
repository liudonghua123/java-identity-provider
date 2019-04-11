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

import java.util.Properties;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Support functions for working with {@link AttributeTranscoder} framework.
 */
public final class TranscoderSupport {

    /** Constructor. */
    private TranscoderSupport() {
        
    }

    /**
     * Pull an {@link AttributeTranscoder} object out of the properties provided.
     * 
     * @param <T> type of supported target object
     * @param ruleset transcoding rules in the form of a {@link Properties} collection
     * 
     * @return an {@link AttributeTranscoder}
     * 
     * @throws ConstraintViolationException if a transcoder cannot be obtained
     */
    @Nonnull public static <T> AttributeTranscoder<T> getTranscoder(@Nonnull final Properties ruleset)
            throws ConstraintViolationException {
        Constraint.isNotNull(ruleset, "Transcoding properties cannot be null");
        
        final Object transcoder = ruleset.get(AttributeTranscoderRegistry.PROP_TRANSCODER);
        Constraint.isTrue(transcoder instanceof AttributeTranscoder<?>, "AttributeTranscoder not found in properties");
        return (AttributeTranscoder<T>) transcoder;
    }

}