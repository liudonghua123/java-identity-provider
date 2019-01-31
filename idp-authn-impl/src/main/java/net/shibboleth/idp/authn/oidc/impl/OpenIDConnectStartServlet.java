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

import javax.annotation.Nonnull;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts Social identity and places it in a request attribute to be used by the IdP's external authentication
 * interface.
 */
public class OpenIDConnectStartServlet extends HttpServlet {

    /** Prefix for the session attribute ids. */
    @Nonnull public static final String SESSION_ATTR_PREFIX =
            "net.shibboleth.idp.authn.oidc.impl.SocialUserOpenIdConnectStartServlet.";

    /** Session attribute id for flow conversation key. */
    @Nonnull public static final String SESSION_ATTR_FLOWKEY = SESSION_ATTR_PREFIX + "key";

    /** Session attribute id for {@link OpenIDConnectContext}. */
    @Nonnull public static final String SESSION_ATTR_SUCTX = SESSION_ATTR_PREFIX + "socialUserOpenIdConnectContext";

    /** Serial UID. */
    private static final long serialVersionUID = -3162157736238514852L;

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(OpenIDConnectStartServlet.class);

    /** Constructor. */
    public OpenIDConnectStartServlet() {
    }

    /** {@inheritDoc} */
    @Override
    public void init(@Nonnull final ServletConfig config) throws ServletException {
        super.init(config);
    }

    /** {@inheritDoc} */
    @Override
    protected void service(@Nonnull final HttpServletRequest httpRequest, 
            @Nonnull final HttpServletResponse httpResponse) throws ServletException, IOException {
       
        try {
            final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
            httpRequest.getSession().setAttribute(SESSION_ATTR_FLOWKEY, key);

            @SuppressWarnings("rawtypes") final ProfileRequestContext profileRequestContext =
                    (ProfileRequestContext) httpRequest.getAttribute(ProfileRequestContext.BINDING_KEY);
            if (profileRequestContext == null) {
                throw new ExternalAuthenticationException("Could not access profileRequestContext from the request");
            }
            final AuthenticationContext authenticationContext =
                    (AuthenticationContext) profileRequestContext.getSubcontext(AuthenticationContext.class);
            if (authenticationContext == null) {
                throw new ExternalAuthenticationException("Could not find AuthenticationContext from the request");
            }
            final OpenIDConnectContext openIDConnectContext =
                    (OpenIDConnectContext) authenticationContext
                            .getSubcontext(OpenIDConnectContext.class);
            if (openIDConnectContext == null) {
                throw new ExternalAuthenticationException(
                        "Could not find OpenIdConnectContext from the request");
            }
            httpRequest.getSession().setAttribute(SESSION_ATTR_SUCTX, openIDConnectContext);
            log.debug("Redirecting user browser to {}", openIDConnectContext.getAuthenticationRequestURI());
            httpResponse.sendRedirect(openIDConnectContext.getAuthenticationRequestURI().toString());
        } catch (final ExternalAuthenticationException e) {
            log.error("Error processing external authentication request", e);           
            throw new ServletException("Error processing external authentication request", e);
        }
       
    }
}
