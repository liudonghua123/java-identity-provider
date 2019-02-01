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

package net.shibboleth.idp.cas.flow.impl;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.cas.config.impl.ConfigLookupFunction;
import net.shibboleth.idp.cas.config.impl.LoginConfiguration;
import net.shibboleth.idp.cas.protocol.ServiceTicketRequest;
import net.shibboleth.idp.cas.protocol.ServiceTicketResponse;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Builds an authentication context from an incoming {@link ServiceTicketRequest} message.
 *
 * @author Marvin S. Addison
 */
public class BuildAuthenticationContextAction extends
        AbstractCASProtocolAction<ServiceTicketRequest, ServiceTicketResponse> {

    /** Profile configuration lookup function. */
    private final ConfigLookupFunction<LoginConfiguration> configLookupFunction =
            new ConfigLookupFunction<>(LoginConfiguration.class);

    @Nonnull
    @Override
    protected Event doExecute(@Nonnull final RequestContext springRequestContext,
            @Nonnull final ProfileRequestContext profileRequestContext){

        final AuthenticationContext ac = new AuthenticationContext();
        ac.setForceAuthn(getCASRequest(profileRequestContext).isRenew());
        ac.setIsPassive(false);

        if (!ac.isForceAuthn()) {
            final LoginConfiguration config = configLookupFunction.apply(profileRequestContext);
            if (config != null) {
                ac.setForceAuthn(config.getForceAuthnPredicate().test(profileRequestContext));
            }
        }
        
        profileRequestContext.addSubcontext(ac, true);
        profileRequestContext.setBrowserProfile(true);
        return null;
    }
    
}