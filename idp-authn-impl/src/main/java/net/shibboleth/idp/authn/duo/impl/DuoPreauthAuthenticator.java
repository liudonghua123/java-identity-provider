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

package net.shibboleth.idp.authn.duo.impl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;

import com.duosecurity.duoweb.DuoWebException;
//import javax.json.JsonObject;
import com.fasterxml.jackson.core.type.TypeReference;

import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URIBuilder;

import net.shibboleth.idp.authn.duo.DuoAuthAPI;
import net.shibboleth.idp.authn.duo.DuoIntegration;
import net.shibboleth.idp.authn.duo.context.DuoAuthenticationContext;

/**
 * Implementation of the the Duo AuthAPI /v2/preauth endpoint.
 */
public class DuoPreauthAuthenticator extends AbstractDuoAuthenticator {

    /** TypeReference for the response generated by the endpoint. */
    @Nonnull private final TypeReference<DuoResponseWrapper<DuoPreauthResponse>> wrapperTypeRef;

    /** Constructor. */
    public DuoPreauthAuthenticator() {
        wrapperTypeRef = new TypeReference<>() {};
    }

    /**
     * Perform an authentication action via the Duo AuthAPI /preauth endpoint.
     * 
     * @param duoContext Duo authentication context to use
     * @param duoIntegration Duo integration to use
     * 
     * @return a {@link DuoPreauthResponse}
     * 
     * @throws DuoWebException if an error occurs
     */
    public DuoPreauthResponse authenticate(@Nonnull final DuoAuthenticationContext duoContext,
            @Nonnull final DuoIntegration duoIntegration) throws DuoWebException {
        try {
            // Prepare the request
            final URI uri = new URIBuilder().setScheme("https").setHost(duoIntegration.getAPIHost())
                    .setPath("/auth/v2/preauth").build();
            final RequestBuilder rb =
                    RequestBuilder.post().setUri(uri).addParameter(DuoAuthAPI.DUO_USERNAME, duoContext.getUsername());
            
            if (duoContext.getClientAddress() != null) {
                rb.addParameter(DuoAuthAPI.DUO_IPADDR, duoContext.getClientAddress());
            }
            
            DuoSupport.signRequest(rb, duoIntegration);
            final HttpUriRequest request = rb.build();

            return doAPIRequest(request, wrapperTypeRef).getResponse();
        } catch (final IOException | URISyntaxException | InvalidKeyException | NoSuchAlgorithmException ex) {
            throw new DuoWebException("Duo AuthAPI preauth request failed: " + ex.getMessage());
        }
    }

}