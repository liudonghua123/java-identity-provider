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

package net.shibboleth.idp.attribute.resolver.ad.impl;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import javax.annotation.Nullable;
import javax.script.ScriptException;
import javax.security.auth.Subject;

import org.apache.commons.codec.digest.DigestUtils;
import org.opensaml.core.xml.XMLObjectBaseTestCase;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.EmptyAttributeValue;
import net.shibboleth.idp.attribute.EmptyAttributeValue.EmptyType;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.XMLObjectAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.DataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.ResolverAttributeDefinitionDependency;
import net.shibboleth.idp.attribute.resolver.ResolverDataConnectorDependency;
import net.shibboleth.idp.attribute.resolver.ResolverTestSupport;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.dc.impl.SAMLAttributeDataConnector;
import net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl;
import net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImplTest;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.saml.authn.principal.AuthenticationMethodPrincipal;
import net.shibboleth.idp.saml.impl.TestSources;
import net.shibboleth.utilities.java.support.collection.LazySet;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.scripting.EvaluableScript;

/** test for {@link net.shibboleth.idp.attribute.resolver.ad.impl.ScriptedIdPAttributeImpl}. */
@SuppressWarnings("javadoc")
public class ScriptedAttributeTest extends XMLObjectBaseTestCase {

    /** The name. */
    private static final String TEST_ATTRIBUTE_NAME = "Scripted";

    /** The language */
    private static final String SCRIPT_LANGUAGE = "JavaScript";

    /** Simple result. */
    private static final String SIMPLE_VALUE = "simple";

    private static Logger log = LoggerFactory.getLogger(ScriptedAttributeTest.class);

    private String fileNameToPath(final String fileName) {
        return "/net/shibboleth/idp/attribute/resolver/impl/ad/" + fileName;
    }

    private EvaluableScript getScript(String fileName) throws ComponentInitializationException, IOException {
        EvaluableScript es = new EvaluableScript ();
        es.setEngineName(SCRIPT_LANGUAGE);
        es.setScript(getClass().getResourceAsStream(fileNameToPath(fileName)));
        es.initialize();
        return es;
    }

    /**
     * Test resolution of an simple script (statically generated data).
     * 
     * @throws ResolutionException ...
     * @throws ComponentInitializationException only if the test will fail
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void simple() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);

        test.setValues(Collections.singletonList(new StringAttributeValue(SIMPLE_VALUE)));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("simple.script"));
        attr.initialize();
        assertNotNull(attr.getScript());

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertTrue(test.equals(val), "Scripted result is the same as bases");
        assertEquals(results.size(), 1, "Scripted result value count");
        assertEquals(((StringAttributeValue)results.iterator().next()).getValue(), SIMPLE_VALUE, "Scripted result contains known value");
    }
    
    /**
     * Test resolution of an simple script (statically generated data).
     * 
     * @throws ResolutionException ...
     * @throws ComponentInitializationException only if the test will fail
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void subject() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {
        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);

        test.setValues(Collections.singletonList(new StringAttributeValue(SIMPLE_VALUE)));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("subjects.script"));
        attr.initialize();
        assertNotNull(attr.getScript());

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertTrue(test.equals(val), "Scripted result is the same as bases");
        assertEquals(results.size(), 4, "Scripted result value count");
        assertTrue(results.contains(new StringAttributeValue(SIMPLE_VALUE)));
        assertTrue(results.contains(new StringAttributeValue(SIMPLE_VALUE+"2")));
        assertTrue(results.contains(new StringAttributeValue(SIMPLE_VALUE+"3")));
        assertTrue(results.contains(new StringAttributeValue(SIMPLE_VALUE+"4")));
    }

    

    /**
     * Test resolution of an script which uses the custom bean.
     * 
     * @throws ResolutionException ...
     * @throws ComponentInitializationException ...
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void custom() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);

        test.setValues(Collections.singletonList(new StringAttributeValue(SIMPLE_VALUE)));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("custom.script"));
        attr.setCustomObject(test.getValues().get(0));
        attr.initialize();
        assertNotNull(attr.getScript());

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertTrue(test.equals(val), "Scripted result is the same as bases");
        assertEquals(results.size(), 1, "Scripted result value count");
        assertEquals(((StringAttributeValue)results.get(0)).getValue(), SIMPLE_VALUE, "Scripted result contains known value");
    }

    /**
     * Test resolution of an simple script (statically generated data).
     * 
     * @throws ResolutionException ...
     * @throws ComponentInitializationException only if the test will fail
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void simple2() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);

        test.setValues(Collections.singletonList(new StringAttributeValue(SIMPLE_VALUE)));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("simple2.script"));
        attr.initialize();
        assertNotNull(attr.getScript());

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertTrue(test.equals(val), "Scripted result is the same as bases");
        assertEquals(results.size(), 1, "Scripted result value count");
        assertEquals(((StringAttributeValue)results.iterator().next()).getValue(), SIMPLE_VALUE, "Scripted result contains known value");
    }

    @Test public void nullValue() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);

        test.setValues(Collections.singletonList(new StringAttributeValue(SIMPLE_VALUE)));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("nullValue.script"));
        attr.initialize();
        assertNotNull(attr.getScript());

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertEquals(results.size(), 1, "Scripted result value count");
        assertEquals(results.iterator().next(), new EmptyAttributeValue(EmptyType.NULL_VALUE),
                "Scripted result contains expected value");
    }

    @Test public void logging() throws Exception {

        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);

        test.setValues(Collections.singletonList(new StringAttributeValue(SIMPLE_VALUE)));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("logging.script"));
        attr.initialize();

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertEquals(results.size(), 2, "Scripted result value count");
    }

    @Test public void simpleWithPredef() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        final IdPAttribute test = new IdPAttribute(TEST_ATTRIBUTE_NAME);
        final IdPAttributeValue attributeValue = new StringAttributeValue(SIMPLE_VALUE);

        test.setValues(Collections.singletonList(attributeValue));

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        assertNull(attr.getScript());
        attr.setId(TEST_ATTRIBUTE_NAME);
        attr.setScript(getScript("simpleWithPredef.script"));
        attr.initialize();
        assertNotNull(attr.getScript());

        final IdPAttribute val = attr.resolve(generateContext());
        final List<IdPAttributeValue> results = val.getValues();

        assertTrue(test.equals(val), "Scripted result is the same as bases");
        assertEquals(results.size(), 1, "Scripted result value count");
        assertEquals(results.iterator().next(), attributeValue, "Scripted result contains known value");
    }

    private ScriptedAttributeDefinition buildTest(final String failingScript, final boolean v8Safe) throws ScriptException,
            IOException, ComponentInitializationException {

        final ScriptedAttributeDefinition attr = new ScriptedAttributeDefinition();
        attr.setId(TEST_ATTRIBUTE_NAME);
        try {
            attr.initialize();
            fail("No script defined");
        } catch (final ComponentInitializationException ex) {
            // OK
        }

        attr.setScript(getScript(failingScript));
        attr.initialize();

        return attr;
    }

    private void failureTest(final String failingScript, final String failingMessage, final boolean v8Safe) throws ScriptException,
            IOException, ComponentInitializationException {
        try {
            buildTest(failingScript, v8Safe).resolve(generateContext());
            fail("Script: '" + failingScript + "' should have thrown an exception: " + failingMessage);
        } catch (final ResolutionException ex) {
            log.trace("Successful exception", ex);
        } catch (final RuntimeException ex) {
            if (ex.getCause() instanceof ResolutionException) {
                log.trace("Successful exception", ex);
            } else {
                throw ex;
            }
        }
    }

    @Test public void fails() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        failureTest("fail1.script", "Unknown method", true);
        failureTest("fail2.script", "Bad output type", true);

        failureTest("fail4.script", "getValues, then getNativeAttributes", true);
        failureTest("fail5.script", "getNativeAttributes, then getValues", true);

        failureTest("fail6.script", "bad type added", false);
    }

    @Test public void addAfterGetValues() throws ResolutionException, ScriptException, IOException,
            ComponentInitializationException {

        final IdPAttribute result = buildTest("addAfterGetValues.script", true).resolve(generateContext());
        final List<IdPAttributeValue> values = result.getValues();
        assertEquals(values.size(), 1);
        assertTrue(values.contains(new StringAttributeValue("newValue")));
    }

    /**
     * Test resolution of an script which looks at the provided attributes.
     * 
     * @throws ResolutionException if the resolve fails
     * @throws ComponentInitializationException only if things go wrong
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void attributes() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        // Set the dependency on the data connector
        final Set<ResolverAttributeDefinitionDependency> ds = new LazySet<>();
        ds.add(TestSources.makeAttributeDefinitionDependency(TestSources.DEPENDS_ON_ATTRIBUTE_NAME_ATTR));
        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId(TEST_ATTRIBUTE_NAME);
        scripted.setScript(getScript("attributes.script"));
        scripted.setAttributeDependencies(ds);
        scripted.initialize();

        // And resolve
        final Set<AttributeDefinition> attrDefinitions = new LazySet<>();
        attrDefinitions.add(scripted);
        attrDefinitions.add(TestSources.populatedStaticAttribute());

        final Set<DataConnector> dataDefinitions = new LazySet<>();
        dataDefinitions.add(TestSources.populatedStaticConnector());

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attrDefinitions, dataDefinitions);
        resolver.initialize();

        final AttributeResolutionContext context = generateContext();
        resolver.resolveAttributes(context);
        final IdPAttribute attribute = context.getResolvedIdPAttributes().get(TEST_ATTRIBUTE_NAME);
        final List<IdPAttributeValue> values = attribute.getValues();

        assertEquals(values.size(), 2);
        assertTrue(values.contains(TestSources.COMMON_ATTRIBUTE_VALUE_RESULT));
        assertTrue(values.contains(TestSources.ATTRIBUTE_ATTRIBUTE_VALUE_RESULT));
    }

    /**
     * Test resolution of an script which looks at the provided attributes.
     * 
     * @throws ResolutionException if the resolve fails
     * @throws ComponentInitializationException only if things go wrong
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void attributesWithNull() throws ResolutionException, ComponentInitializationException,
            ScriptException, IOException {

        final List<IdPAttributeValue> values = new ArrayList<>(3);
        values.add(TestSources.COMMON_ATTRIBUTE_VALUE_RESULT);
        values.add(new EmptyAttributeValue(EmptyType.NULL_VALUE));
        final IdPAttribute attr = new IdPAttribute(TestSources.DEPENDS_ON_ATTRIBUTE_NAME_ATTR);

        attr.setValues(values);

        final AttributeResolutionContext resolutionContext =
                ResolverTestSupport.buildResolutionContext(ResolverTestSupport.buildDataConnector("connector1", attr));
        final ResolverDataConnectorDependency depend = TestSources.makeDataConnectorDependency("connector1", TestSources.DEPENDS_ON_ATTRIBUTE_NAME_ATTR);

        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId(TEST_ATTRIBUTE_NAME);
        scripted.setScript(getScript("attributes.script"));
        scripted.setDataConnectorDependencies(Collections.singleton(depend));
        scripted.initialize();

        final IdPAttribute result = scripted.resolve(resolutionContext);

        final List<IdPAttributeValue> outValues = result.getValues();

        assertEquals(outValues.size(), 2);
        assertTrue(values.contains(TestSources.COMMON_ATTRIBUTE_VALUE_RESULT));
        assertTrue(values.contains(new EmptyAttributeValue(EmptyType.NULL_VALUE)));
    }

    @Test public void nonString() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        // Set the dependency on the data connector
        final Set<ResolverAttributeDefinitionDependency> ds = new LazySet<>();
        ds.add(TestSources.makeAttributeDefinitionDependency(TestSources.DEPENDS_ON_SECOND_ATTRIBUTE_NAME));

        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId(TEST_ATTRIBUTE_NAME);
        scripted.setScript(getScript("attributes2.script"));
        scripted.setAttributeDependencies(ds);
        scripted.initialize();

        // And resolve
        final Set<AttributeDefinition> attrDefinitions = new HashSet<>(3);
        attrDefinitions.add(scripted);
        final AttributeDefinition nonString =
                TestSources.nonStringAttributeDefiniton(TestSources.DEPENDS_ON_SECOND_ATTRIBUTE_NAME);
        attrDefinitions.add(nonString);
        attrDefinitions.add(TestSources.populatedStaticAttribute());

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attrDefinitions, null);
        resolver.initialize();

        final AttributeResolutionContext context = generateContext();
        resolver.resolveAttributes(context);
        final IdPAttribute attribute = context.getResolvedIdPAttributes().get(TEST_ATTRIBUTE_NAME);
        final List<IdPAttributeValue> values = attribute.getValues();

        assertEquals(values.size(), 2);
        for (final IdPAttributeValue value : values) {
            if (!(value instanceof XMLObjectAttributeValue)) {
                fail("Wrong type: " + value.getClass().getName());
            }
        }
    }

    /**
     * Test resolution of an script which looks at the provided request context.
     * 
     * @throws ResolutionException if the resolve fails
     * @throws ComponentInitializationException only if the test has gone wrong
     * @throws ScriptException ...
     * @throws IOException ...
     */
    @Test public void context() throws ResolutionException, ComponentInitializationException, ScriptException,
            IOException {

        // Set the dependency on the data connector
        final Set<ResolverDataConnectorDependency> ds = new LazySet<>();
        ds.add(TestSources.makeDataConnectorDependency(TestSources.STATIC_CONNECTOR_NAME,
                TestSources.DEPENDS_ON_ATTRIBUTE_NAME_CONNECTOR));

        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId(TEST_ATTRIBUTE_NAME);
        scripted.setScript(getScript("context.script"));
        scripted.setDataConnectorDependencies(ds);
        scripted.initialize();

        // And resolve
        final Set<AttributeDefinition> attrDefinitions = new LazySet<>();
        attrDefinitions.add(scripted);
        attrDefinitions.add(TestSources.populatedStaticAttribute());

        final Set<DataConnector> dataDefinitions = new LazySet<>();
        dataDefinitions.add(TestSources.populatedStaticConnector());

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attrDefinitions, dataDefinitions);
        resolver.initialize();

        final AttributeResolutionContext context = generateContext();

        try {
            resolver.resolveAttributes(context);
        } catch (final ResolutionException e) {
            fail("resolution failed", e);
        }

        final IdPAttribute attribute = context.getResolvedIdPAttributes().get(TEST_ATTRIBUTE_NAME);
        final Collection<IdPAttributeValue> values = attribute.getValues();

        assertEquals(values.size(), 5, "looking for context");
        assertTrue(values.contains(new StringAttributeValue("AttributeResolutionContext")));
        assertTrue(values.contains(new StringAttributeValue("ProfileRequestContext")));
        assertTrue(values.contains(new StringAttributeValue(TestSources.PRINCIPAL_ID)));
        assertTrue(values.contains(new StringAttributeValue(TestSources.IDP_ENTITY_ID)));
        assertTrue(values.contains(new StringAttributeValue(TestSources.SP_ENTITY_ID)));
    }

    protected IdPAttribute runExample(final String exampleScript, final String exampleData, final String attributeName)
            throws ScriptException, IOException, ComponentInitializationException {
        final SAMLAttributeDataConnector connector = new SAMLAttributeDataConnector();
        connector.setAttributesStrategy(new Locator(exampleData));
        connector.setId("Connector");

        final Set<ResolverDataConnectorDependency> ds =
                Collections.singleton(TestSources.makeDataConnectorDependency("Connector", null));

        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId(attributeName);
        scripted.setScript(getScript(exampleScript));
        scripted.setDataConnectorDependencies(ds);

        final Set<DataConnector> dataDefinitions = Collections.singleton((DataConnector) connector);
        final Set<AttributeDefinition> attrDefinitions = Collections.singleton((AttributeDefinition) scripted);

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attrDefinitions, dataDefinitions);
        connector.initialize();
        scripted.initialize();
        resolver.initialize();

        final AttributeResolutionContext context =
                TestSources.createResolutionContext("principal", "issuer", "recipient");

        try {
            resolver.resolveAttributes(context);
        } catch (final ResolutionException e) {
            fail("resolution failed", e);
        }

        return context.getResolvedIdPAttributes().get(attributeName);

    }

    @Test public void examples() throws ScriptException, IOException, ComponentInitializationException {

        IdPAttribute attribute = runExample("example1.script", "example1.attribute.xml", "swissEduPersonUniqueID");

        assertEquals(((StringAttributeValue)attribute.getValues().iterator().next()).getValue(),
                DigestUtils.md5Hex("12345678some#salt#value#12345679") + "@switch.ch");

        attribute = runExample("example2.script", "example2.attribute.xml", "eduPersonAffiliation");
        HashSet<IdPAttributeValue> set = new HashSet<>(attribute.getValues());
        assertEquals(set.size(), 3);
        assertTrue(set.contains(new StringAttributeValue("affiliate")));
        assertTrue(set.contains(new StringAttributeValue("student")));
        assertTrue(set.contains(new StringAttributeValue("staff")));

        attribute = runExample("example3.script", "example3.attribute.xml", "eduPersonAffiliation");
        set = new HashSet<>(attribute.getValues());
        assertEquals(set.size(), 2);
        assertTrue(set.contains(new StringAttributeValue("member")));
        assertTrue(set.contains(new StringAttributeValue("staff")));

        attribute = runExample("example3.script", "example3.attribute.2.xml", "eduPersonAffiliation");
        set = new HashSet<>(attribute.getValues());
        assertEquals(set.size(), 3);
        assertTrue(set.contains(new StringAttributeValue("member")));
        assertTrue(set.contains(new StringAttributeValue("staff")));
        assertTrue(set.contains(new StringAttributeValue("walkin")));

        attribute = runExample("example4.script", "example4.attribute.xml", "eduPersonEntitlement");
        set = new HashSet<>(attribute.getValues());
        assertEquals(set.size(), 1);
        assertTrue(set.contains(new StringAttributeValue("urn:mace:dir:entitlement:common-lib-terms")));

        attribute = runExample("example4.script", "example4.attribute.2.xml", "eduPersonEntitlement");
        set = new HashSet<>(attribute.getValues());
        assertEquals(set.size(), 2);
        assertTrue(set.contains(new StringAttributeValue("urn:mace:dir:entitlement:common-lib-terms")));
        assertTrue(set.contains(new StringAttributeValue("LittleGreenMen")));

        attribute = runExample("example4.script", "example4.attribute.3.xml", "eduPersonEntitlement");
        assertNull(attribute);

    }

    @Test public void v2Context() throws IOException, ComponentInitializationException, ResolutionException,
            ScriptException {

        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId("scripted");
        scripted.setScript(getScript("requestContext.script"));
        scripted.initialize();

        final IdPAttribute result = scripted.resolve(generateContext());
        final HashSet<IdPAttributeValue> set = new HashSet<>(result.getValues());
        assertEquals(set.size(), 3);
        assertTrue(set.contains(new StringAttributeValue(TestSources.PRINCIPAL_ID)));
        assertTrue(set.contains(new StringAttributeValue(TestSources.IDP_ENTITY_ID)));
        assertTrue(set.contains(new StringAttributeValue(TestSources.SP_ENTITY_ID)));

    }

    @Test public void unimplementedV2Context() throws IOException, ComponentInitializationException,
            ResolutionException, ScriptException {

        final ScriptedAttributeDefinition scripted = new ScriptedAttributeDefinition();
        scripted.setId("scripted");
        scripted.setScript(getScript("requestContextUnimplemented.script"));
        scripted.initialize();

        final IdPAttribute result = scripted.resolve(generateContext());
        assertEquals(result.getValues().iterator().next(), new StringAttributeValue("AllDone"));

    }

    private static AttributeResolutionContext generateContext() {
        final AttributeResolutionContext ctx = TestSources.createResolutionContext(TestSources.PRINCIPAL_ID, TestSources.IDP_ENTITY_ID,
                TestSources.SP_ENTITY_ID);
        final SubjectContext sc = ctx.getParent().getSubcontext(SubjectContext.class, true);
        
        final Map<String, AuthenticationResult> authnResults = sc.getAuthenticationResults();
        Subject subject = new Subject();
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE));
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE+"2"));
        
        authnResults.put("one", new AuthenticationResult("1", subject));
        subject = new Subject();
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE+"3"));
        subject.getPrincipals().add(new AuthenticationMethodPrincipal(SIMPLE_VALUE+"4"));
        authnResults.put("two", new AuthenticationResult("2", subject));
        return ctx;
    }

    final class Locator implements Function<AttributeResolutionContext, List<Attribute>> {

        final EntityAttributes obj;

        public Locator(final String file) {
            obj = (EntityAttributes) unmarshallElement(fileNameToPath(file));
        }

        /** {@inheritDoc} */
        @Nullable public List<Attribute> apply(@Nullable final AttributeResolutionContext input) {
            return obj.getAttributes();
        }

    }
}
