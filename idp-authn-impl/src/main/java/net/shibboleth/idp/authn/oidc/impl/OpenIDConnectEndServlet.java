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

package net.shibboleth.idp.authn.oidc.impl;

import java.io.IOException;
import java.net.URISyntaxException;


import javax.annotation.Nonnull;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;




/**
 * Extracts Social identity and places it in a request attribute to be used by the IdP's external authentication
 * interface.
 */
public class OpenIDConnectEndServlet extends HttpServlet {

    /** Serial UID. */
    private static final long serialVersionUID = -3162157736238514852L;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(OpenIDConnectEndServlet.class);

    /** Constructor. */
    public OpenIDConnectEndServlet() {
    }

    /** {@inheritDoc} */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
    }

    /** {@inheritDoc} */
    @Override
    protected void service(@Nonnull final HttpServletRequest httpRequest,
            @Nonnull final HttpServletResponse httpResponse) throws ServletException, IOException {
       
        try {
            final HttpSession session = httpRequest.getSession();
            if (session == null) {
                throw new ExternalAuthenticationException("No session exist, this URL shouldn't be called directly!");
            }
            final String key = StringSupport.trimOrNull((String) httpRequest.getSession()
                    .getAttribute(OpenIDConnectStartServlet.SESSION_ATTR_FLOWKEY));
            if (key == null) {
                throw new ExternalAuthenticationException(
                        "Could not find value for " + OpenIDConnectStartServlet.SESSION_ATTR_FLOWKEY);
            }
            final OpenIDConnectContext openIDConnectContext =
                    (OpenIDConnectContext) httpRequest.getSession()
                            .getAttribute(OpenIDConnectStartServlet.SESSION_ATTR_SUCTX);
            if (openIDConnectContext == null) {
                throw new ExternalAuthenticationException(
                        "Could not find value for " + OpenIDConnectStartServlet.SESSION_ATTR_SUCTX);
            }
            log.debug("Attempting URL {}?{}", httpRequest.getRequestURL(), httpRequest.getQueryString());
            try {
                openIDConnectContext.setAuthenticationResponseURI(httpRequest);
            } catch (final URISyntaxException e) {
                throw new ExternalAuthenticationException("Could not parse response URI", e);
            }
            ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
        } catch (final ExternalAuthenticationException e) {
            log.error("Could not finish the external authentication", e);          
            throw new ServletException("Error finishing the external authentication", e);
        }
        
    }
}
