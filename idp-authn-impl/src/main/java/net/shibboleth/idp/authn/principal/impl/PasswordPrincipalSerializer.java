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

package net.shibboleth.idp.authn.principal.impl;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonStructure;
import javax.json.stream.JsonGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import net.shibboleth.idp.authn.principal.AbstractPrincipalSerializer;
import net.shibboleth.idp.authn.principal.PasswordPrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;

/**
 * Principal serializer for {@link PasswordPrincipal} that encrypts the password.
 */
@ThreadSafe
public class PasswordPrincipalSerializer extends AbstractPrincipalSerializer<String> {

    /** Field name of password. */
    @Nonnull @NotEmpty private static final String PASSWORD_FIELD = "PW";

    /** Pattern used to determine if input is supported. */
    private static final Pattern JSON_PATTERN = Pattern.compile("^\\{\"PW\":.*\\}$");

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(PasswordPrincipalSerializer.class);

    /** Data sealer. */
    @Nullable private DataSealer sealer;
    
    /** JSON object bulder factory. */
    @Nonnull private final JsonBuilderFactory objectBuilderFactory;

    /** Constructor. */
    public PasswordPrincipalSerializer() {
        objectBuilderFactory = Json.createBuilderFactory(null);
    }
    
    /**
     * Set the {@link DataSealer} to use.
     * 
     * @param theSealer encrypting component to use
     */
    public void setDataSealer(@Nullable final DataSealer theSealer) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        sealer = theSealer;
    }

    /** {@inheritDoc} */
    public boolean supports(@Nonnull final Principal principal) {
        if (principal instanceof PasswordPrincipal) {
            if (sealer == null) {
                log.error("No DataSealer was provided, unable to support PasswordPrincipal serialization");
                return false;
            }
            return true;
        }
        return false;
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String serialize(@Nonnull final Principal principal) throws IOException {
        
        if (sealer == null) {
            throw new IOException("No DataSealer was provided, unable to support PasswordPrincipal serialization");
        }
        
        final StringWriter sink = new StringWriter(32);
        try (final JsonGenerator gen = getJsonGenerator(sink)) {
            gen.writeStartObject()
               .write(PASSWORD_FIELD, sealer.wrap(principal.getName(),
                       Instant.now().plus(Duration.ofDays(365))))
               .writeEnd();
        } catch (final DataSealerException e) {
            throw new IOException(e);
        }
        return sink.toString();
    }
    
    /** {@inheritDoc} */
    public boolean supports(@Nonnull @NotEmpty final String value) {
        if (JSON_PATTERN.matcher(value).matches()) {
            if (sealer == null) {
                log.error("No DataSealer was provided, unable to support PasswordPrincipal deserialization");
                return false;
            }
            return true;
        }
        return false;
    }

    /** {@inheritDoc} */
    @Nullable public PasswordPrincipal deserialize(@Nonnull @NotEmpty final String value) throws IOException {
        
        if (sealer == null) {
            throw new IOException("No DataSealer was provided, unable to support PasswordPrincipal deserialization");
        }

        try (final JsonReader reader = getJsonReader(new StringReader(value))) {
            
            final JsonStructure st = reader.read();
            if (!(st instanceof JsonObject)) {
                throw new IOException("Found invalid data structure while parsing PasswordPrincipal");
            }
            
            final JsonObject obj = (JsonObject) st;
            final JsonString str = obj.getJsonString(PASSWORD_FIELD);
            if (str != null) {
                if (!Strings.isNullOrEmpty(str.getString())) {
                    try {
                        return new PasswordPrincipal(sealer.unwrap(str.getString()));
                    } catch (final DataSealerException e) {
                        throw new IOException(e);
                    }
                }
                log.warn("Skipping null/empty PasswordPrincipal");
            }
            return null;
        } catch (final JsonException e) {
            throw new IOException("Found invalid data structure while parsing PasswordPincipal", e);
        }
    }

    /**
     * Get a {@link JsonObjectBuilder} in a thread-safe manner.
     * 
     * @return  an object builder
     */
    @Nonnull private synchronized JsonObjectBuilder getJsonObjectBuilder() {
        return objectBuilderFactory.createObjectBuilder();
    }

    /**
     * Get a {@link JsonArrayBuilder} in a thread-safe manner.
     * 
     * @return  an array builder
     */
    @Nonnull private synchronized JsonArrayBuilder getJsonArrayBuilder() {
        return objectBuilderFactory.createArrayBuilder();
    }
    
}