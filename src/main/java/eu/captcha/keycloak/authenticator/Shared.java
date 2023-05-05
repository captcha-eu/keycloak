package eu.captcha.keycloak.authenticator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Shared {
    public static boolean validateCaptchaAt(String sol, String secret) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.captcha.eu/validate"))
                .POST(HttpRequest.BodyPublishers.ofString(sol, StandardCharsets.UTF_8))
                .header("Rest-Key", secret)
                .header("Content-Type", "application/json")
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String responseBody = response.body();

        
        Pattern pattern = Pattern.compile("\"success\":\\s*(true|false)");
        Matcher matcher = pattern.matcher(responseBody);

        if (matcher.find()) {
            return Boolean.parseBoolean(matcher.group(1));
        }

        return false;

    }
}
