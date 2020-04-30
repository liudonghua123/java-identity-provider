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

package net.shibboleth.idp.attribute.filter.policyrule.impl;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.filter.PolicyRequirementRule.Tristate;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.idp.attribute.filter.matcher.impl.AbstractMatcherPolicyRuleTest;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.saml.authn.principal.AuthenticationMethodPrincipal;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.DestroyedComponentException;
import net.shibboleth.utilities.java.support.component.UninitializedComponentException;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponentException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.scripting.EvaluableScript;

/** {@link ScriptedPolicyRule} unit test. */
@ThreadSafe
public class ScriptedPolicyRuleTest extends AbstractMatcherPolicyRuleTest {

    /** A script that returns null. */
    private EvaluableScript nullReturnScript;

    /** A script that returns Boolean.True. */
    private EvaluableScript trueReturnScript;

    /** A script that returns Boolean.false . */
    private EvaluableScript falseReturnScript;

    /** Another script that returns Boolean.true . */
    private EvaluableScript prcReturnScript;

    /** Another script that returns Boolean.true . */
    private EvaluableScript scReturnScript;

    /** A script that returns an object other than a set. */
    private EvaluableScript invalidReturnObjectScript;

    /** A script that returns the custom object. */
    private EvaluableScript customReturnScript;

    @BeforeClass public void setup() throws Exception {
        super.setUp();

        filterContext = new AttributeFilterContext();

        nullReturnScript = new EvaluableScript();
        nullReturnScript.setEngineName("JavaScript");
        nullReturnScript.setScript("null;");
        nullReturnScript.initialize();

        invalidReturnObjectScript = new EvaluableScript();
        invalidReturnObjectScript.setEngineName("JavaScript");
        invalidReturnObjectScript.setScript("load('nashorn:mozilla_compat.js');new java.lang.String();");
        invalidReturnObjectScript.initialize();

        trueReturnScript = new EvaluableScript();
        trueReturnScript.setEngineName("JavaScript");
        trueReturnScript.setScript("new java.lang.Boolean(true);");
        trueReturnScript.initialize();

        falseReturnScript = new EvaluableScript();
        falseReturnScript.setEngineName("JavaScript");
        falseReturnScript.setScript("new java.lang.Boolean(false);");
        falseReturnScript.initialize();

        prcReturnScript = new EvaluableScript();
        prcReturnScript.setEngineName("JavaScript");
        prcReturnScript.setScript("new java.lang.Boolean(profileContext.getClass().getName().equals(\"org.opensaml.profile.context.ProfileRequestContext\"));");
        prcReturnScript.initialize();

        customReturnScript = new EvaluableScript();
        customReturnScript.setEngineName("JavaScript");
        customReturnScript.setScript("custom;");
        customReturnScript.initialize();

        scReturnScript = new EvaluableScript();
        scReturnScript.setEngineName("JavaScript");
        scReturnScript.setScript("new java.lang.Boolean(subjects[0].getPrincipals().iterator().next().getName().equals(\"FOO\"));");
        scReturnScript.initialize();
    }

    @Test public void testNullArguments() throws Exception {
        final ScriptedPolicyRule rule = newScriptedPolicyRule(trueReturnScript);
        rule.setId("Test");
        rule.initialize();

        try {
            rule.matches(null);
            fail();
        } catch (final ConstraintViolationException e) {
            // expected this
        }

        try {
            newScriptedPolicyRule(null);
            fail();
        } catch (final ConstraintViolationException e) {
            // expected this
        }
    }

    @Test public void testNullReturnScript() throws Exception {
        final ScriptedPolicyRule rule = newScriptedPolicyRule(nullReturnScript);
        rule.setId("Test");
        rule.initialize();

        assertEquals(rule.matches(filterContext), Tristate.FAIL);
    }

    @Test public void testInvalidReturnObjectValue() throws Exception {
        final ScriptedPolicyRule rule = newScriptedPolicyRule(invalidReturnObjectScript);
        rule.setId("Test");
        rule.initialize();

        assertEquals(rule.matches(filterContext), Tristate.FAIL);
    }

    @Test public void testInitTeardown() throws ComponentInitializationException {
        final ScriptedPolicyRule rule = newScriptedPolicyRule(trueReturnScript);

        boolean thrown = false;
        try {
            rule.matches(filterContext);
        } catch (final UninitializedComponentException e) {
            thrown = true;
        }
        assertTrue(thrown, "matches before init");

        rule.setId("Test");
        rule.initialize();
        rule.matches(filterContext);

        thrown = false;
        try {
            rule.setScript(trueReturnScript);
        } catch (final UnmodifiableComponentException e) {
            thrown = true;
        }

        rule.destroy();

        thrown = false;
        try {
            rule.initialize();
        } catch (final DestroyedComponentException e) {
            thrown = true;
        }
        assertTrue(thrown, "init after destroy");

        thrown = false;
        try {
            rule.matches(filterContext);
        } catch (final DestroyedComponentException e) {
            thrown = true;
        }
        assertTrue(thrown, "matches after destroy");

    }

    @SuppressWarnings("unlikely-arg-type")
    @Test public void testEqualsHashToString() {
        final ScriptedPolicyRule rule = newScriptedPolicyRule(trueReturnScript);

        rule.toString();

        assertFalse(rule.equals(null));
        assertTrue(rule.equals(rule));
        assertFalse(rule.equals(this));

        ScriptedPolicyRule other = newScriptedPolicyRule(trueReturnScript);

        assertTrue(rule.equals(other));
        assertEquals(rule.hashCode(), other.hashCode());

        other = newScriptedPolicyRule(nullReturnScript);

        assertFalse(rule.equals(other));
        assertNotSame(rule.hashCode(), other.hashCode());

    }
    
    @Test public void testPredicate() throws ComponentInitializationException {
        ScriptedPolicyRule rule = newScriptedPolicyRule(nullReturnScript);
        rule.setId("test");
        rule.initialize();

        rule = newScriptedPolicyRule(trueReturnScript);
        rule.setId("test");
        rule.initialize();
        assertEquals(rule.matches(filterContext), Tristate.TRUE);

        rule = newScriptedPolicyRule(customReturnScript);
        rule.setCustomObject(Boolean.valueOf(true));
        rule.setId("test");
        rule.initialize();
        assertEquals(rule.matches(filterContext), Tristate.TRUE);

        rule = newScriptedPolicyRule(falseReturnScript);
        rule.setId("test");
        rule.initialize();
        assertEquals(rule.matches(filterContext), Tristate.FALSE);

        rule = newScriptedPolicyRule(prcReturnScript);
        rule.setId("test");
        rule.initialize();
        
        assertEquals(rule.matches(filterContext), Tristate.FAIL);
        
        final ProfileRequestContext prc = new ProfileRequestContext(); 
        prc.getSubcontext(RelyingPartyContext.class, true).addSubcontext(filterContext);
        final SubjectContext sc = prc.getSubcontext(SubjectContext.class, true);
        
        final Subject subject = new Subject();
        sc.getAuthenticationResults().put("one", new AuthenticationResult("1", subject));
        
        assertEquals(rule.matches(filterContext), Tristate.TRUE);

        final ScriptedPolicyRule scRule = newScriptedPolicyRule(scReturnScript);
        scRule.setId("ScTest");
        scRule.initialize();
        subject.getPrincipals().add(new AuthenticationMethodPrincipal("BAR"));
        assertEquals(scRule.matches(filterContext), Tristate.FALSE);

        subject.getPrincipals().clear();
        subject.getPrincipals().add(new AuthenticationMethodPrincipal("FOO"));
        assertEquals(scRule.matches(filterContext), Tristate.TRUE);
    }

    static public  ScriptedPolicyRule newScriptedPolicyRule(final EvaluableScript script) {
        final ScriptedPolicyRule what = new ScriptedPolicyRule();
        what.setScript(script);
        return what;
    }


}
