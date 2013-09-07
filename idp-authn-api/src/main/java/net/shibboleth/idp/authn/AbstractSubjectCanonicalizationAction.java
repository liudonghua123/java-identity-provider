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

package net.shibboleth.idp.authn;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.context.SubjectCanonicalizationContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.ProfileException;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

/**
 * A base class for subject canonicalization actions.
 * 
 * In addition to the work performed by {@link AbstractProfileAction}, this action also looks up and makes available the
 * {@link SubjectCanonicalizationContext}.
 * 
 * Authentication action implementations should override
 * {@link #doExecute(ProfileRequestContext, SubjectCanonicalizationContext)}
 * 
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 */
public abstract class AbstractSubjectCanonicalizationAction extends AbstractProfileAction {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractSubjectCanonicalizationAction.class);
    
    /**
     * Strategy used to find the {@link SubjectCanonicalizationContext} from the
     * {@link ProfileRequestContext}.
     */
    @Nonnull private Function<ProfileRequestContext, SubjectCanonicalizationContext> scCtxLookupStrategy;
    
    /** SubjectCanonicalizationContext to operate on. */
    @Nullable private SubjectCanonicalizationContext scContext;
    
    /** Match patterns and replacement strings to apply. */
    @Nonnull @NonnullElements private List<Pair<Pattern,String>> transforms;
    
    /** Constructor. */
    public AbstractSubjectCanonicalizationAction() {
        super();
        
        scCtxLookupStrategy = new ChildContextLookup(SubjectCanonicalizationContext.class, false);
        transforms = Collections.emptyList();
    }

    /**
     * Set the context lookup strategy.
     * 
     * @param strategy  lookup strategy function for {@link SubjectCanonicalizationContext}.
     */
    public void setLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SubjectCanonicalizationContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        scCtxLookupStrategy = Constraint.isNotNull(strategy, "Strategy cannot be null");
    }

    /**
     * A collection of regular expression and replacement pairs.
     * 
     * @param newTransforms collection of replacement transforms
     */
    public void setTransforms(@Nonnull @NonnullElements Collection<Pair<String, String>> newTransforms) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotNull(newTransforms, "Transforms collection cannot be null");
        
        transforms = new ArrayList();
        for (Pair<String,String> p : newTransforms) {
            Pattern pattern = Pattern.compile(StringSupport.trimOrNull(p.getFirst()));
            transforms.add(new Pair(pattern, Constraint.isNotNull(
                    StringSupport.trimOrNull(p.getSecond()), "Replacement expression cannot be null")));
        }
    }

    
    /** {@inheritDoc} */
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) throws ProfileException {
        scContext = scCtxLookupStrategy.apply(profileRequestContext);
        if (scContext == null) {
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        
        if (doPreExecute(profileRequestContext, scContext)) {
            return super.doPreExecute(profileRequestContext);
        } else {
            return false;
        }
    }

    /** {@inheritDoc} */
    protected final void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) throws ProfileException {

        doExecute(profileRequestContext, scContext);
    }

    /**
     * Performs this c14n action's pre-execute step. Default implementation just returns true.
     * 
     * @param profileRequestContext the current IdP profile request context
     * @param c14nContext the current subject canonicalization context
     * 
     * @return true iff execution should continue
     * 
     * @throws SubjectCanonicalizationException thrown if there is a problem performing the authentication action
     */
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final SubjectCanonicalizationContext c14nContext) throws SubjectCanonicalizationException {
        return true;
    }
    
    /**
     * Performs this authentication action. Default implementation throws an exception.
     * 
     * @param profileRequestContext the current IdP profile request context
     * @param c14nContext the current subject canonicalization context
     * 
     * @throws SubjectCanonicalizationException thrown if there is a problem performing the authentication action
     */
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final SubjectCanonicalizationContext c14nContext) throws SubjectCanonicalizationException {
        throw new UnsupportedOperationException("This action is not implemented");
    }
    
    /**
     * Apply any configured regular expression replacements to an input value and return the result.
     * 
     * @param input the input string
     * 
     * @return  the result of applying the expressions
     */
    @Nonnull @NotEmpty protected String applyTransforms(@Nonnull @NotEmpty final String input) {
        
        if (transforms.isEmpty()) {
            return input;
        }
        
        String s = input;
        
        for (Pair<Pattern,String> p : transforms) {            
            final Matcher m = p.getFirst().matcher(s);
            log.debug("applying replacement expression '{}' against input '{}'", p.getFirst().pattern(), s);
            s = m.replaceAll(p.getSecond());
            log.debug("result of replacement is '{}'", s);
        }
        
        return s;
    }
}