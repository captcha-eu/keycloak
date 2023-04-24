package eu.captcha.keycloak.authenticator;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import java.net.URI;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import java.io.InputStream;
import javax.ws.rs.core.MultivaluedMap;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import java.util.Map;
import java.util.Optional;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import java.net.http.HttpResponse;
import java.io.IOException;


public class RegistrationCaptcha implements FormAction, FormActionFactory {
    public static final String CAPTCHA_RESPONSE = "captcha-eu-response";
    public static final String CAPTCHA_REFERENCE_CATEGORY = "captcha-eu";
    public static final String PUBLIC_KEY = "captcha.eu.public.key";
    public static final String REST_KEY = "captcha.eu.rest.key";
    public static final String CAPTCHA_FAILED = "Captcha.eu failed to verify";
    public static final String PROVIDER_ID = "registration-captcha-action";

    private static final String CUSTOM_TEMPLATE = "captcha.ftl";


    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

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
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
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
    public static boolean validateCaptchaAt(String sol, String secret) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://w19.captcha.at/validate"))
                .POST(HttpRequest.BodyPublishers.ofString(sol, StandardCharsets.UTF_8))
                .header("Rest-Key", secret)
                .header("Content-Type", "application/json")
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String responseBody = response.body();

        Logger logger = Logger.getLogger("my.logger.name");
logger.info(responseBody);

        int start = responseBody.indexOf("success\":") + 9;
        int end = responseBody.indexOf(",", start);
        String successValue = responseBody.substring(start, end);
        return Boolean.parseBoolean(successValue);
    }
    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        Logger logger = Logger.getLogger("my.logger.name");
        logger.info("HJA");

        boolean success = false;



        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String secret = captchaConfig.getConfig().get(REST_KEY);

        String sol = formData.getFirst("captcha_at_solution");

        try {
            success = validateCaptchaAt(sol, secret);
        } catch (Exception e) {
            success = false;
        }
        if (!success) {
            errors.add(new FormMessage(null, CAPTCHA_FAILED));
            formData.remove(CAPTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }
        context.success();
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
