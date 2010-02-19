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

package edu.internet2.middleware.shibboleth.idp.consent.persistence;

import java.util.Date;
import java.util.List;

import edu.internet2.middleware.shibboleth.idp.consent.entities.AgreedTermsOfUse;
import edu.internet2.middleware.shibboleth.idp.consent.entities.Attribute;
import edu.internet2.middleware.shibboleth.idp.consent.entities.AttributeReleaseConsent;
import edu.internet2.middleware.shibboleth.idp.consent.entities.Principal;
import edu.internet2.middleware.shibboleth.idp.consent.entities.RelyingParty;
import edu.internet2.middleware.shibboleth.idp.consent.entities.TermsOfUse;

/**
 *
 */
public interface Storage {

    public abstract int createAgreedTermsOfUse(final Principal principal, final TermsOfUse termsOfUse,
            final Date agreeDate);

    public abstract int createAttributeReleaseConsent(final Principal principal, final RelyingParty relyingParty,
            final Attribute attribute, final Date releaseDate);

    public abstract long createPrincipal(final Principal principal);

    public abstract long createRelyingParty(final RelyingParty relyingParty);

    public abstract int deleteAgreedTermsOfUse(final Principal principal, final TermsOfUse termsOfUse);

    public abstract int deleteAgreedTermsOfUses(final Principal principal);

    public abstract int deleteAttributeReleaseConsent(final Principal principal);

    public abstract int deleteAttributeReleaseConsent(final Principal principal, final RelyingParty relyingParty,
            final Attribute attribute);

    public abstract int deleteAttributeReleaseConsents(final Principal principal);

    public abstract int deleteAttributeReleaseConsents(final Principal principal, final RelyingParty relyingParty);

    public abstract int deletePrincipal(final Principal principal);

    public abstract int deleteRelyingParty(final RelyingParty relyingParty);

    public abstract long findPrincipal(final Principal principal);

    public abstract long findRelyingParty(final RelyingParty relyingParty);

    public abstract AgreedTermsOfUse readAgreedTermsOfUse(final Principal principal, final TermsOfUse termsOfUse);

    public abstract List<AgreedTermsOfUse> readAgreedTermsOfUses(final Principal principal);

    public abstract AttributeReleaseConsent readAttributeReleaseConsent(final Principal principal, final RelyingParty relyingParty,
            Attribute attribute);

    public abstract List<AttributeReleaseConsent> readAttributeReleaseConsents(final Principal principal);

    public abstract List<AttributeReleaseConsent> readAttributeReleaseConsents(final Principal principal,
            RelyingParty relyingParty);

    public abstract Principal readPrincipal(final Principal principal);

    public abstract RelyingParty readRelyingParty(final RelyingParty relyingParty);

    public abstract int updateAgreedTermsOfUse(final Principal principal, final TermsOfUse termsOfUse,
            final Date agreeDate);
    
    public abstract int updateAttributeReleaseConsent(final Principal principal, final RelyingParty relyingParty,
            final Attribute attribute, final Date releaseDate);

    public abstract int updatePrincipal(final Principal principal);

    public abstract int updateRelyingParty(final RelyingParty relyingParty);

}