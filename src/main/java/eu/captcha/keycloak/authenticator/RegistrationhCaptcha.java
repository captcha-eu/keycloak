package eu.captcha.keycloak.authenticator;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class RegistrationhCaptcha implements FormAction, FormActionFactory {
    public static final String CAPTCHA_RESPONSE = "captcha-eu-response";
    public static final String CAPTCHA_REFERENCE_CATEGORY = "captcha-eu";
    public static final String PUBLIC_KEY = "captcha.eu.public.key";
    public static final String REST_KEY = "captcha.eu.rest.key";
    public static final String PROVIDER_ID = "registration-captcha-action";

    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "captcha.eu";
    }

    @Override
    public String getReferenceCategory() {
        return CAPTCHA_REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Adds the seamless integrated captcha.eu GDPR compliant captcha";
    }


    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(PUBLIC_KEY) == null
                ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        String publicKey = captchaConfig.getConfig().get(PUBLIC_KEY);
        form.setAttribute("captchaEnabled", true);
        form.setAttribute("captchaEUPublicKey", publicKey);
        form.addScript("https://www.captcha.eu/sdk.js");

    }

    @Override
    public void validate(ValidationContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha = formData.getFirst(CAPTCHA_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String secret = captchaConfig.getConfig().get(REST_KEY);

            success = validateRecaptcha(context, success, captcha, secret);
        }
        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            formData.remove(CAPTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;

        }

    }


    protected boolean validateRecaptcha(ValidationContext context, boolean success, String captcha, String secret) {
      return true;
    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(PUBLIC_KEY);
        property.setLabel("Public Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Public Key");
        CONFIG_PROPERTIES.add(property);


        property = new ProviderConfigProperty();
        property.setName(REST_KEY);
        property.setLabel("RestKey");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("RestKey");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

}
