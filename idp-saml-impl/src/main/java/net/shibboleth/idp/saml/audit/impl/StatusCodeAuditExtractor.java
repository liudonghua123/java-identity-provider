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

package net.shibboleth.idp.saml.audit.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml1.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.logic.Constraint;

/** {@link Function} that returns the StatusCode from a response. */
public class StatusCodeAuditExtractor implements Function<ProfileRequestContext,String> {

    /** Lookup strategy for message to read from. */
    @Nonnull private final Function<ProfileRequestContext,SAMLObject> responseLookupStrategy;
    
    /**
     * Constructor.
     *
     * @param strategy lookup strategy for message
     */
    public StatusCodeAuditExtractor(@Nonnull final Function<ProfileRequestContext,SAMLObject> strategy) {
        responseLookupStrategy = Constraint.isNotNull(strategy, "Response lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable public String apply(@Nullable final ProfileRequestContext input) {
        final SAMLObject response = responseLookupStrategy.apply(input);
        if (response != null) {
            if (response instanceof Response) {
                final org.opensaml.saml.saml1.core.StatusCode sc =
                        ((Response) response).getStatus() != null
                                ? ((Response) response).getStatus().getStatusCode() : null;
                if (sc != null && sc.getValue() != null) {
                    return sc.getValue().getLocalPart();
                }
            } else if (response instanceof StatusResponseType) {
                final org.opensaml.saml.saml2.core.StatusCode sc =
                        ((StatusResponseType) response).getStatus() != null
                                ? ((StatusResponseType) response).getStatus().getStatusCode() : null;
                if (sc != null) {
                    return sc.getValue();
                }
            }
        }
        
        return null;
    }

}