package eu.captcha.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;


public class UsernamePasswordFormFactory implements AuthenticatorFactory {
    private String restKey;
    private String publicKey;
    public static final String PROVIDER_ID = "auth-username-password-form-captcha";
    public static final UsernamePasswordForm SINGLETON = new UsernamePasswordForm();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        this.restKey = config.get("restKey");
        this.publicKey = config.get("publicKey");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return "captcha";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "captcha.eu: Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "captcha.eu Validate Username + Password";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty("restKey", "Rest Key", "", ProviderConfigProperty.STRING_TYPE, this.restKey),
                new ProviderConfigProperty("publicKey", "Public Key", "", ProviderConfigProperty.STRING_TYPE, this.publicKey)
        );
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
