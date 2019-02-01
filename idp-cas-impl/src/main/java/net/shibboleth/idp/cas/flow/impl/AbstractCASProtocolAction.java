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

import java.util.function.Function;

import javax.annotation.Nonnull;

import net.shibboleth.idp.cas.protocol.ProtocolContext;
import net.shibboleth.idp.cas.service.Service;
import net.shibboleth.idp.cas.service.ServiceContext;
import net.shibboleth.idp.cas.ticket.Ticket;
import net.shibboleth.idp.cas.ticket.TicketContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;

/**
 * Base class for CAS protocol actions.
 * 
 * @param <RequestType> request
 * @param <ResponseType> response
 *
 * @author Marvin S. Addison
 */
public abstract class AbstractCASProtocolAction<RequestType, ResponseType> extends AbstractProfileAction {

    /** Looks up a CAS protocol context from IdP profile request context. */
    private final Function<ProfileRequestContext,ProtocolContext<RequestType,ResponseType>> protocolLookupFunction;

    /** Constructor. */
    public AbstractCASProtocolAction() {
        protocolLookupFunction = new ChildContextLookup(ProtocolContext.class, true);
    }

    /**
     * Get the CAS request.
     * 
     * @param prc profile request context
     * @return CAS request
     */
    @Nonnull
    protected RequestType getCASRequest(final ProfileRequestContext prc) {
        final RequestType request = getProtocolContext(prc).getRequest();
        if (request == null) {
            throw new IllegalStateException("CAS protocol request not found");
        }
        return request;
    }

    /**
     * Set the CAS request.
     * 
     * @param prc profile request context
     * @param request CAS request
     */
    protected void setCASRequest(final ProfileRequestContext prc, @Nonnull final RequestType request) {
        getProtocolContext(prc).setRequest(Constraint.isNotNull(request, "CAS request cannot be null"));
    }

    /**
     * Get the CAS response.
     * 
     * @param prc profile request context
     * @return CAS response
     */
    @Nonnull
    protected ResponseType getCASResponse(final ProfileRequestContext prc) {
        final ResponseType response = getProtocolContext(prc).getResponse();
        if (response == null) {
            throw new IllegalStateException("CAS protocol response not found");
        }
        return response;
    }

    /**
     * Set the CAS response.
     * 
     * @param prc profile request context
     * @param response CAS response
     */
    protected void setCASResponse(final ProfileRequestContext prc, @Nonnull final ResponseType response) {
        getProtocolContext(prc).setResponse(Constraint.isNotNull(response, "CAS response cannot be null"));
    }

    /**
     * Get the CAS ticket.
     * 
     * @param prc profile request context
     * @return CAS ticket
     */
    @Nonnull protected Ticket getCASTicket(final ProfileRequestContext prc) {
        final TicketContext context = getProtocolContext(prc).getSubcontext(TicketContext.class);
        if (context == null || context.getTicket() == null) {
            throw new IllegalStateException("CAS protocol ticket not found");
        }
        return context.getTicket();
    }

    /**
     * Set the CAS ticket.
     * 
     * @param prc profile request context
     * @param ticket CAS ticket
     */
    protected void setCASTicket(final ProfileRequestContext prc, @Nonnull final Ticket ticket) {
        getProtocolContext(prc).addSubcontext(
                new TicketContext(Constraint.isNotNull(ticket, "CAS ticket cannot be null")));
    }

    /**
     * Get the CAS service.
     * 
     * @param prc profile request context
     * @return CAS service
     */
    @Nonnull protected Service getCASService(final ProfileRequestContext prc) {
        final ServiceContext context = getProtocolContext(prc).getSubcontext(ServiceContext.class);
        if (context == null || context.getService() == null) {
            throw new IllegalStateException("CAS protocol service not found");
        }
        return context.getService();
    }

    /**
     * Set the CAS service.
     * 
     * @param prc profile request context
     * @param service CAS service
     */
    protected void setCASService(final ProfileRequestContext prc, @Nonnull final Service service) {
        getProtocolContext(prc).addSubcontext(
                new ServiceContext(Constraint.isNotNull(service, "CAS service cannot be null")));
    }

    /**
     * Get the CAS protocol context.
     * 
     * @param prc profile request context
     * @return CAS protocol context
     */
    @Nonnull protected ProtocolContext<RequestType, ResponseType> getProtocolContext(final ProfileRequestContext prc) {
        final ProtocolContext<RequestType, ResponseType> casCtx = protocolLookupFunction.apply(prc);
        if (casCtx == null) {
            throw new IllegalArgumentException("CAS ProtocolContext not found in ProfileRequestContext");
        }
        return casCtx;
    }
}
