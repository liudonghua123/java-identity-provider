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

package net.shibboleth.idp.saml.impl.profile.saml1;

import javax.annotation.Nonnull;

import net.shibboleth.ext.spring.webflow.Event;
import net.shibboleth.ext.spring.webflow.Events;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionSupport;
import org.opensaml.profile.ProfileException;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import net.shibboleth.idp.saml.profile.SamlEventIds;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.messaging.context.BasicMessageMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml1.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

/**
 * Adds the <code>InResponseTo</code> attribute to outgoing {@link Response} retrieved from the
 * {@link ProfileRequestContext#getOutboundMessageContext()}. If there was no message ID on the inbound message than
 * nothing is added to the response.
 */
@Events({@Event(id = EventIds.PROCEED_EVENT_ID),
        @Event(id = SamlEventIds.NO_IN_MSG_ID, description = "Inbound message did not contain an ID")})
public class AddInResponseToToResponse extends AbstractProfileAction<Object, Response> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AddInResponseToToResponse.class);

    /** {@inheritDoc} */
    protected org.springframework.webflow.execution.Event
            doExecute(@Nonnull final RequestContext springRequestContext,
                    @Nonnull final ProfileRequestContext<Object, Response> profileRequestContext)
                            throws ProfileException {
        log.debug("Action {}: Attempting to add InResponseTo to outgoing Response", getId());

        final String inMsgId = getInboundMessageId(profileRequestContext);
        if (inMsgId == null) {
            log.debug("Action {}: Inbound message did not have an ID, no InResponse to added to Response", getId());
            return ActionSupport.buildEvent(this, SamlEventIds.NO_IN_MSG_ID);
        }

        final Response response = profileRequestContext.getOutboundMessageContext().getMessage();

        log.debug("Action {}: Add InResponseTo message ID {} to Response {}",
                new Object[] {getId(), inMsgId, response.getID(),});
        response.setInResponseTo(inMsgId);
        return ActionSupport.buildProceedEvent(this);
    }

    /**
     * Gets the ID of the inbound message.
     * 
     * @param profileRequestContext current request context
     * 
     * @return the inbound message ID or null if the was no ID
     */
    private String getInboundMessageId(final ProfileRequestContext<Object, Response> profileRequestContext) {
        final MessageContext inMsgCtx = profileRequestContext.getInboundMessageContext();
        if (inMsgCtx == null) {
            log.debug("Action {}: no inbound message context available", getId());
            return null;
        }

        final BasicMessageMetadataContext inMsgMetadataCtx = inMsgCtx.getSubcontext(BasicMessageMetadataContext.class);
        if (inMsgMetadataCtx == null) {
            log.debug("Action {}: no inbound message metadata context available", getId());
            return null;
        }

        return StringSupport.trimOrNull(inMsgMetadataCtx.getMessageId());
    }
}