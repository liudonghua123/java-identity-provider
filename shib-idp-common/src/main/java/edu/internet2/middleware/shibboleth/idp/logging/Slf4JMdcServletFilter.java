/*
 * Copyright 2010 University Corporation for Advanced Internet Development, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.logging;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.MDC;

import edu.internet2.middleware.shibboleth.idp.Version;

/**
 * Servlet filter that sets some interesting MDC attributes as the request comes in and clears the MDC as the response
 * is returned.
 */
public class Slf4JMdcServletFilter implements Filter {

    /** {@inheritDoc} */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        try {
            MDC.put(Version.MDC_ATTRIBUTE, Version.getVersionString());
            // TODO populate the MDC will other interesting things
        } finally {
            MDC.clear();
        }

    }

    /** {@inheritDoc} */
    public void init(FilterConfig filterConfig) throws ServletException {
        // nothing to do
    }

    /** {@inheritDoc} */
    public void destroy() {
        // nothing to do
    }
}