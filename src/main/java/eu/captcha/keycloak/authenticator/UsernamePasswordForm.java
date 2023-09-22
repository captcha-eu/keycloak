package eu.captcha.keycloak.authenticator;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log = ServicesLogger.LOGGER;


    private Response createFailureResponse(AuthenticationFlowContext context, String errorMessage) {
        return context.form()
                .setError(errorMessage)
                .createErrorPage(Response.Status.UNAUTHORIZED);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;


        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String secret = captchaConfig.getConfig().get("restKey");
        String sol = formData.getFirst("captcha_at_solution");

        try {
            success = Shared.validateCaptchaAt(sol, secret);
        } catch (Exception e) {
            success = false;
        }
        //success = false;
        if (!success) {
            context.failure(AuthenticationFlowError.INVALID_USER, createFailureResponse(context, "Captcha.eu: Failed to Validate captcha"));
            return;
        }


        if (formData.containsKey("cancel")) {
            context.cancelLogin();
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
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            LoginFormsProvider form = context.form();

            AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
            Map<String, String> config = authenticatorConfig.getConfig();


            String publicKey = config.get("publicKey");
            log.info(config);
            form.setAttribute("captchaEnabled", true);
            form.setAttribute("captchaEUPublicKey", publicKey);
            form.addScript("https://www.captcha.eu/sdk.js");

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

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
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
