/*
 * Copyright 2009 University Corporation for Advanced Internet Development, Inc.
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

package edu.internet2.middleware.shibboleth.idp.consent.entities;

import java.util.Date;

/**
 *
 */
public class AgreedTermsOfUse {
    TermsOfUse termsOfUse;

    Date agreeDate;

    /**
     * @return Returns the agreeDate.
     */
    public Date getAgreeDate() {
        return agreeDate;
    }

    /**
     * @return Returns the TermsOfUse.
     */
    public TermsOfUse getTermsOfUse() {
        return termsOfUse;
    }

    /**
     * @param agreeDate The agreeDate to set.
     */
    public void setAgreeDate(final Date agreeDate) {
        this.agreeDate = agreeDate;
    }

    /**
     * @param tou The TermsOfUse to set.
     */
    public void setTermsOfUse(final TermsOfUse termsOfUse) {
        this.termsOfUse = termsOfUse;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((termsOfUse == null) ? 0 : termsOfUse.hashCode());
        return result;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AgreedTermsOfUse other = (AgreedTermsOfUse) obj;
        if (termsOfUse == null) {
            if (other.termsOfUse != null)
                return false;
        } else if (!termsOfUse.equals(other.termsOfUse))
            return false;
        return true;
    }

}
