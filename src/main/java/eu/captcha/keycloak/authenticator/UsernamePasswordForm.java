package eu.captcha.keycloak.authenticator;


import jakarta.ws.rs.core.MultivaluedHashMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Map;

public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log = ServicesLogger.LOGGER;


    // Every rendering of the login form needs the captcha widget, including re-renders after a failed attempt
    private void addCaptcha(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        Map<String, String> config = authenticatorConfig.getConfig();

        LoginFormsProvider form = context.form();
        form.setAttribute("captchaEnabled", true);
        form.setAttribute("captchaEUPublicKey", config.get("publicKey"));
        form.addScript("https://www.captcha.eu/sdk.js");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        boolean success = false;

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String secret = captchaConfig.getConfig().get("restKey");
        String sol = formData.getFirst("captcha_at_solution");

        try {
            success = Shared.validateCaptchaAt(sol, secret);
        } catch (Exception e) {
            success = false;
        }
        if (!success) {
            // Re-render the login form (with a fresh captcha) instead of a dead-end error page
            MultivaluedMap<String, String> retryData = new MultivaluedHashMap<>();
            String username = formData.getFirst(AuthenticationManager.FORM_USERNAME);
            if (username != null) retryData.add(AuthenticationManager.FORM_USERNAME, username);
            context.form().setFormData(retryData);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challenge(context, "Captcha.eu: Failed to Validate captcha"));
            return;
        }

        if (!validateForm(context, formData)) {
            return;
        }
        context.success();
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getSession());

        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    // Used by validateUserAndPassword() for wrong password, unknown user, brute force lockout, ...
    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        addCaptcha(context);
        return super.challenge(context, error, field);
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        addCaptcha(context);
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }
}
