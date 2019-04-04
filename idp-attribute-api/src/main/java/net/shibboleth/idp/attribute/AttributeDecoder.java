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

package net.shibboleth.idp.attribute;

import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;

import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Attribute decoders convert a protocol specific object into an {@link IdPAttribute}. Implementations must take
 * into account that objects may contain data of multiple types. An implementation encountering a value type it
 * does not understand may either decide to ignore it or throw an {@link AttributeDecodingException}.
 * 
 * <p>Decoders implement a {@link Predicate} interface to determine their applicability to a request.</p>
 * 
 * <p>Decoders <strong>MUST</strong> be thread-safe and stateless and <strong>MUST</strong> implement appropriate
 * {@link Object#equals(Object)} and {@link Object#hashCode()} methods.</p>
 * 
 * @param <DecodedType> the type of object supported
 */
@ThreadSafe
public interface AttributeDecoder<DecodedType> {

    /**
     * Get the identifier of the protocol targeted by this decoder.
     * 
     * @return identifier of the protocol targeted by this encounter
     */
    @Nonnull @NotEmpty String getProtocol();
        
    /**
     * Get an activation condition for this decoder.
     * 
     * @return  a predicate indicating whether the decoder should be applied
     */
    @Nonnull Predicate<ProfileRequestContext> getActivationCondition();

    /**
     * Decode the supplied object into a protocol-neutral representation.
     * 
     * @param input the object to decode
     * 
     * @return the object the attribute was decoded into
     * 
     * @throws AttributeDecodingException if unable to successfully decode object
     */
    @Nonnull IdPAttribute decode(@Nonnull final DecodedType input) throws AttributeDecodingException;

}