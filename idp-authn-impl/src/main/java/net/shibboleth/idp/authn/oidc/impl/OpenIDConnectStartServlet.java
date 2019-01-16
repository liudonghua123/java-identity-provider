package net.shibboleth.idp.authn.oidc.impl;

import java.io.IOException;

import javax.servlet.annotation.WebServlet;
import javax.annotation.Nonnull;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.oidc.context.OpenIDConnectContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts Social identity and places it in a request attribute to be used by the IdP's external authentication
 * interface.
 */
public class OpenIDConnectStartServlet extends HttpServlet {

    /** Prefix for the session attribute ids. */
    public static final String SESSION_ATTR_PREFIX =
            "net.shibboleth.idp.authn.oidc.impl.SocialUserOpenIdConnectStartServlet.";

    /** Session attribute id for flow conversation key. */
    public static final String SESSION_ATTR_FLOWKEY = SESSION_ATTR_PREFIX + "key";

    /** Session attribute id for {@link OpenIDConnectContext}. */
    public static final String SESSION_ATTR_SUCTX = SESSION_ATTR_PREFIX + "socialUserOpenIdConnectContext";

    /** Serial UID. */
    private static final long serialVersionUID = -3162157736238514852L;

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OpenIDConnectStartServlet.class);

    /** Constructor. */
    public OpenIDConnectStartServlet() {
    }

    /** {@inheritDoc} */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
    }

    /** {@inheritDoc} */
    @Override
    protected void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {
        log.trace("Entering");
        try {
            final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
            httpRequest.getSession().setAttribute(SESSION_ATTR_FLOWKEY, key);

            @SuppressWarnings("rawtypes") final ProfileRequestContext profileRequestContext =
                    (ProfileRequestContext) httpRequest.getAttribute(ProfileRequestContext.BINDING_KEY);
            if (profileRequestContext == null) {
                throw new ExternalAuthenticationException("Could not access profileRequestContext from the request");
            }
            final AuthenticationContext authenticationContext =
                    (AuthenticationContext) profileRequestContext.getSubcontext(AuthenticationContext.class);
            if (authenticationContext == null) {
                throw new ExternalAuthenticationException("Could not find AuthenticationContext from the request");
            }
            final OpenIDConnectContext openIDConnectContext =
                    (OpenIDConnectContext) authenticationContext
                            .getSubcontext(OpenIDConnectContext.class);
            if (openIDConnectContext == null) {
                throw new ExternalAuthenticationException(
                        "Could not find SocialUserOpenIdConnectContext from the request");
            }
            httpRequest.getSession().setAttribute(SESSION_ATTR_SUCTX, openIDConnectContext);
            log.debug("Redirecting user browser to {}", openIDConnectContext.getAuthenticationRequestURI());
            httpResponse.sendRedirect(openIDConnectContext.getAuthenticationRequestURI().toString());
        } catch (ExternalAuthenticationException e) {
            log.error("Error processing external authentication request", e);
            log.trace("Leaving");
            throw new ServletException("Error processing external authentication request", e);
        }
        log.trace("Leaving");
    }
}
