package eu.captcha.keycloak.authenticator;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class Shared {
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
}
