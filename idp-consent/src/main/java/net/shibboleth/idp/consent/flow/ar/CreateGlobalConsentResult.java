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

package net.shibboleth.idp.consent.flow.ar;

import java.io.IOException;
import java.util.Collections;

import javax.annotation.Nonnull;

import net.shibboleth.idp.consent.Consent;
import net.shibboleth.idp.consent.flow.storage.AbstractConsentStorageAction;
import net.shibboleth.idp.consent.storage.ConsentResult;
import net.shibboleth.idp.profile.context.ProfileInterceptorContext;
import net.shibboleth.idp.profile.interceptor.ProfileInterceptorResult;

import org.joda.time.DateTime;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Attribute consent action to create a consent result representing global consent to be stored in a storage service.
 */
public class CreateGlobalConsentResult extends AbstractConsentStorageAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(CreateGlobalConsentResult.class);

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final ProfileInterceptorContext interceptorContext) {

        try {
            final Consent globalConsent = new Consent();
            globalConsent.setId(Consent.WILDCARD);
            globalConsent.setApproved(true);

            final String value =
                    getConsentSerializer().serialize(Collections.singletonMap(globalConsent.getId(), globalConsent));

            final Long lifetime = getConsentFlowDescriptor().getLifetime();
            Long expiration = null;
            if (lifetime != null) {
                expiration = DateTime.now().plus(lifetime).getMillis();
            }

            final ProfileInterceptorResult result = new ConsentResult(getContext(), getKey(), value, expiration);

            log.debug("{} Created global consent result '{}'", getLogPrefix(), result);

            interceptorContext.setResult(result);

        } catch (IOException e) {
            log.debug("{} Unable to serialize consent", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
        }
    }
}
