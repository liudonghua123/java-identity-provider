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

package net.shibboleth.idp.authn.spnego.impl;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class that manages context establishment for the SPNEGO GSS-API mechanism.
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc2853.txt">RFC 2853 - Generic Security Service API Version 2 : Java
 *      Bindings</a>
 * @see http://www.ietf.org/rfc/rfc4178.txt
 */
public class GSSContextAcceptor {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(GSSContextAcceptor.class);

    /** The OID representing the SPNEGO pseudo-mechanism. */
    @Nonnull private final Oid spnegoOid;

    /** The Kerberos settings. */
    @Nonnull private KerberosSettings kerberosSettings;

    /** The realm in use. */
    @Nullable private KerberosRealmSettings realmSettings;
    
    /** The Kerberos login module and server login state. */
    @Nullable private GSSAcceptorLoginModule krbLoginModule;

    /** Server credentials used during context establishment. */
    @Nullable private GSSCredential serverCreds;

    /** The GSSContext being established, or that was established. */
    @Nullable private GSSContext context;

    /**
     * Constructor.
     * 
     * @param settings the KerberosSettings to use
     * 
     * @throws GSSException if an error occurs establishing server credentials
     */
    public GSSContextAcceptor(@Nonnull final KerberosSettings settings) throws GSSException {
        kerberosSettings = settings;
        try {
            spnegoOid = new Oid("1.3.6.1.5.5.2");
        } catch (final GSSException e) {
            log.debug("Unable to create SPNEGO mechanism OID");
            throw e;
        }
    }

    /**
     * Return the GSS security context.
     * 
     * @return the context
     */
    @Nullable public GSSContext getContext() {
        return context;
    }

    /**
     * Process the inbound GSS token.
     * 
     * <p>During the first (and likely only) token step, we will also establish the server's
     * credentials in the process. If additional round trips occur, this will be detected
     * and the previous partial context will be used.</p>
     * 
     * @see <a href="http://www.ietf.org/rfc/rfc4121.txt">RFC 4121: Kerberos for GSSAPI.</a>
     * 
     * @param inToken token generated by the peer
     * @param offset the offset within the inToken where the token begins
     * @param len the length of the token
     * 
     * @return a byte[] containing the token to be sent to the peer, or null if no output token is needed
     * @throws Exception if an error occurs
     */
    @Nullable public byte[] acceptSecContext(@Nonnull final byte[] inToken, final int offset, final int len)
            throws Exception {

        if (context == null) {
            log.trace("Processing first GSS input token");
            return acceptFirstToken(inToken, offset, len);
        }
        
        log.trace("Processing an additional GSS input token");
        byte[] tokenOut = context.acceptSecContext(inToken, offset, len);
        if (context.isEstablished()) {
            log.trace("Security context established");
        } else {
            log.trace("Security context partially established");
        }
        return tokenOut;
    }
    
    /**
     * Dispose of the context and the server's credentials, and do a logout of the Kerberos login module.
     */
    public void logout() {
        if (context != null) {
            try {
                context.dispose();
                context = null;
            } catch (final GSSException e) {
                log.error("GSS-API context disposal failed", e);
            }
        }
        if (serverCreds != null) {
            try {
                serverCreds.dispose();
                serverCreds = null;
            } catch (GSSException e) {
                log.error("GSS-API credentials disposal failed", e);
            }
        }
        if (krbLoginModule != null) {
            try {
                krbLoginModule.logout();
                krbLoginModule = null;
            } catch (final LoginException e) {
                log.error("Server credentials logout failed", e);
            }
        }
    }

    /**
     * Process the first inbound GSS token.
     * 
     * @param inToken token generated by the peer
     * @param offset the offset within the inToken where the token begins
     * @param len the length of the token
     * 
     * @return a byte[] containing the token to be sent to the peer, or null if no output token is needed
     * @throws LoginException if an error occurs
     */
    @Nullable private byte[] acceptFirstToken(@Nonnull final byte[] inToken, final int offset, final int len)
            throws LoginException {

        // We loop over each realm to determine which one might work.
        for (final KerberosRealmSettings realm : kerberosSettings.getRealms()) {
            
            log.debug("Validating the first GSS input token against realm: {}", realm.getRealmName());
            try {
                createGSSContext(realm);
                final byte[] tokenOut = context.acceptSecContext(inToken, offset, len);
                realmSettings = realm;
                if (getContext().isEstablished()) {
                    log.trace("Security context fully established");
                } else {
                    log.trace("Security context partially established");
                }
                return tokenOut;
            } catch (final Exception e) {
                log.warn("Error establishing security context", e);
                logout();
            }
        }
        
        throw new LoginException("None of the configured realms were usable");
    }
    
    /**
     * Establish initial server credentials and create a GSS acceptor context based on then. 
     * 
     * @param realm realm settings to use
     * 
     * @throws GSSException thrown if GSS context could not be created
     * @throws LoginException thrown if login failed
     * @throws PrivilegedActionException thrown if GSS credentials could not be created
     */
    private void createGSSContext(@Nonnull final KerberosRealmSettings realm)
            throws GSSException, LoginException, PrivilegedActionException {
        
        // Establish server login credentials.
        Subject krbSubject = null;
        krbLoginModule = new GSSAcceptorLoginModule(realm, kerberosSettings.getRefreshKrb5Config(),
                kerberosSettings.getLoginModuleClassName());
        try {
            krbSubject = krbLoginModule.login();
        } catch (final LoginException e) {
            log.error("Server login error using realm: {}", realm.getRealmName());
            throw e;
        }
        log.trace("Server login successful using realm: {}", realm.getRealmName());

        /*
         * Create the server credentials and an acceptor context.
         */
        log.trace("Creating GSS credentials and context");
        final GSSManager manager = GSSManager.getInstance();
        try {
            serverCreds = getServerCredential(krbSubject);
            context = manager.createContext(serverCreds);
        } catch (final PrivilegedActionException e) {
            log.error("Error creating GSS credentials", e);
            throw e;
        } catch (final GSSException e) {
            log.error("Error creating GSS acceptor context", e);
            throw e;
        }
        log.trace("GSS acceptor context created");
    }

    /**
     * Create the credential for the GSS-API.
     * 
     * @param subject Kerberos subject to create the credentials from
     * 
     * @return the created GSS credentials
     * @throws PrivilegedActionException thrown if server credentials could not be created
     */
    @Nonnull private GSSCredential getServerCredential(@Nonnull final Subject subject)
            throws PrivilegedActionException {
        final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
            public GSSCredential run() throws GSSException {
                GSSManager manager = GSSManager.getInstance();
                GSSCredential newServerCreds =
                        manager.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, spnegoOid,
                                GSSCredential.ACCEPT_ONLY);
                return newServerCreds;
            }
        };
        return Subject.doAs(subject, action);
    }

}