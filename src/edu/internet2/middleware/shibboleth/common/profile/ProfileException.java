/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.common.profile;

import edu.internet2.middleware.shibboleth.common.ShibbolethException;

/**
 * Exception for errors occuring within a profile handler.
 */
public class ProfileException extends ShibbolethException {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 7450785279045338311L;

    /**
     * Constructor.
     */
    public ProfileException() {
        super();
    }
    
    /**
     * Constructor.
     * 
     * @param message exception message
     */
    public ProfileException(String message) {
        super(message);
    }
    
    /**
     * Constructor.
     * 
     * @param wrappedException exception to be wrapped by this one
     */
    public ProfileException(Exception wrappedException) {
        super(wrappedException);
    }
    
    /**
     * Constructor.
     * 
     * @param message exception message
     * @param wrappedException exception to be wrapped by this one
     */
    public ProfileException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }
}