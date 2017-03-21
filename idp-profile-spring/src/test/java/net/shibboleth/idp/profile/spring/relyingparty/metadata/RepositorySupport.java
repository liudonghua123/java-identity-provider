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

package net.shibboleth.idp.profile.spring.relyingparty.metadata;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Support class for working with the project version control repository.
 */
public final class RepositorySupport {
    
    /** Constructor. */
    private RepositorySupport() { } 
    
    /**
     * Build an HTTPS resource URL for the selected repository name and path.
     * 
     * @param repoName the repository name.  If Git, do not include the ".git" suffix.
     * @param resourcePath The relative resource path within the repository, e.g. "foo/bar/baz/file.txt"
     * @return the HTTPS resource URL
     */
    public static String buildHTTPSResourceURL(@Nonnull final String repoName, @Nonnull final String resourcePath) {
        return buildHTTPResourceURL(repoName, resourcePath, true);
    }
    
    /**
     * Build an HTTP/HTTPS resource URL for the selected repository name and path.
     * 
     * @param repoName the repository name.  If Git, do not include a trailing ".git" suffix for bare repos.
     * @param resourcePath The relative resource path within the repository, e.g. "foo/bar/baz/file.txt"
     * @param https if true, use https if possible, otherwise use http
     * @return the HTTP(S) resource URL
     */
    public static String buildHTTPResourceURL(@Nonnull final String repoName, @Nonnull final String resourcePath, 
            final boolean https) {
        
        final String repo = Constraint.isNotNull(StringSupport.trimOrNull(repoName), 
                "Repository name was null or empty");
        String path = Constraint.isNotNull(StringSupport.trimOrNull(resourcePath), 
                "Resource path was null or empty");
        
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        
        return String.format("%s://git.shibboleth.net/view/?p=%s.git&a=blob_plain&f=%s&hb=master", 
                https ? "https" : "http", repo, path);
    }

}
