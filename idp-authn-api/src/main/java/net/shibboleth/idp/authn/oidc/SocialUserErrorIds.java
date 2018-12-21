

package net.shibboleth.idp.authn.oidc;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Constants to use for error results related to social user authentication.
 */
public final class SocialUserErrorIds {

    /**
     * Generic ID for exception thrown.
     */
    @Nonnull
    @NotEmpty
    public static final String EXCEPTION = "SocialUserException";

    /**
     * ID for user canceling the authentication.
     */
    @Nonnull
    @NotEmpty
    public static final String USER_CANCELED = "SocialUserCanceled";

    /** private constructor to prohibit use of it. */
    private SocialUserErrorIds() {

    };

}
