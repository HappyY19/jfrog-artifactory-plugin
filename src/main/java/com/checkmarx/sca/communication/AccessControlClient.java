package com.checkmarx.sca.communication;

import com.checkmarx.sca.communication.exceptions.AuthenticationFailedException;
import com.checkmarx.sca.communication.exceptions.FailedToRefreshTokenException;
import com.checkmarx.sca.communication.exceptions.UnexpectedAuthenticationResponseException;
import com.checkmarx.sca.communication.exceptions.UserIsNotAuthenticatedException;
import com.checkmarx.sca.communication.models.AccessControlCredentials;
import com.checkmarx.sca.communication.models.AccessControlToken;
import com.checkmarx.sca.communication.models.AuthenticationHeader;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;

public class AccessControlClient {
    private final String TokenEndpointPath = "identity/connect/token";
    private final String ClientId = "sca_resource_owner";
    private final String OAuthScope = "sca_api";
    private final Logger _logger;
    private final HttpClient _httpClient;
    private final String _authenticationUrl;
    private AccessControlToken _accessControlToken;
    private AccessControlCredentials _accessControlCredentials;

    public AccessControlClient(@Nonnull PluginConfiguration configuration, @Nonnull Logger logger) {
        this._logger = logger;
        String authenticationUrl = configuration.getPropertyOrDefault(ConfigurationEntry.AUTHENTICATION_URL);
        if (!authenticationUrl.endsWith("/")) {
            authenticationUrl = authenticationUrl + "/";
        }

        this._authenticationUrl = authenticationUrl;
        this._httpClient = HttpClient.newHttpClient();
    }

    public boolean Authenticate(@NotNull AccessControlCredentials accessControlCredentials) {
        try {
            this._accessControlCredentials = accessControlCredentials;
            this.AuthenticateResourceOwner();
        } catch (Exception var3) {
            this._logger.debug("Authentication failed. Working without authentication.");
            this._logger.error(var3.getMessage(), var3);
            return false;
        }

        this._logger.debug("Authentication configured successfully.");
        return true;
    }

    public AuthenticationHeader GetAuthorizationHeader() {
        if (this._accessControlToken == null) {
            throw new UserIsNotAuthenticatedException();
        } else if (this._accessControlToken.isActive()) {
            return this.GenerateTokenAuthorizationHeader();
        } else {
            boolean success = this.RefreshTokenAsync();
            if (!success) {
                throw new FailedToRefreshTokenException();
            } else {
                return this.GenerateTokenAuthorizationHeader();
            }
        }
    }

    public String GetAuthorizationToken() {
        if (this._accessControlToken == null) {
            throw new UserIsNotAuthenticatedException();
        } else if (this._accessControlToken.isActive()) {
            return this._accessControlToken.getAccessToken();
        } else {
            boolean success = this.RefreshTokenAsync();
            if (!success) {
                throw new FailedToRefreshTokenException();
            } else {
                return this._accessControlToken.getAccessToken();
            }
        }
    }

    public String getTenantId() {
        return this.getDataStringFromToken("tenant_id");
    }

    private String getDataStringFromToken(String field) {
        JsonObject contentObject = this.getJsonObjectFromToken();
        return contentObject.get(field).getAsString();
    }

    private JsonObject getJsonObjectFromToken() {
        String token = this.GetAuthorizationToken();
        String[] chunks = token.split("\\.");
        String tokenContent = chunks[1];
        byte[] contentDecoded = Base64.getUrlDecoder().decode(tokenContent);
        return (JsonObject) (new Gson()).fromJson(String.valueOf(contentDecoded), JsonObject.class);
    }

    private void AuthenticateResourceOwner() throws ExecutionException, InterruptedException {
        HttpRequest resourceOwnerGrantRequest = this.CreateResourceOwnerGrantRequest();
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient
                .sendAsync(resourceOwnerGrantRequest, BodyHandlers.ofString());
        HttpResponse<String> authenticateResponse = (HttpResponse) responseFuture.get();
        if (authenticateResponse.statusCode() != 200) {
            throw new AuthenticationFailedException(authenticateResponse.statusCode());
        } else {
            AccessControlToken accessControlToken;
            try {
                accessControlToken = (AccessControlToken) (
                        new Gson()).fromJson((String) authenticateResponse.body(), AccessControlToken.class);
            } catch (Exception var6) {
                throw new UnexpectedAuthenticationResponseException((String) authenticateResponse.body());
            }

            if (accessControlToken != null && accessControlToken.isBearerToken()) {
                this._accessControlToken = accessControlToken;
            } else {
                throw new UnexpectedAuthenticationResponseException((String) authenticateResponse.body());
            }
        }
    }

    private HttpRequest CreateResourceOwnerGrantRequest() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("scope", "sca_api");
        parameters.put("client_id", "sca_resource_owner");
        parameters.put("username", this._accessControlCredentials.getUsername());
        parameters.put("password", this._accessControlCredentials.getPassword());
        parameters.put("grant_type", "password");
        parameters.put("acr_values", String.format("Tenant:%s", this._accessControlCredentials.getTenant()));
        String form = (String) parameters.entrySet().stream().map((e) -> {
            String var10000 = (String) e.getKey();
            return var10000 + "=" + URLEncoder.encode((String) e.getValue(), StandardCharsets.UTF_8);
        }).collect(Collectors.joining("&"));
        return HttpRequest.newBuilder(URI.create(
                String.format("%s%s", this._authenticationUrl, "identity/connect/token")))
                .header("content-type", "application/x-www-form-urlencoded")
                .POST(BodyPublishers.ofString(form))
                .build();
    }

    private boolean RefreshTokenAsync() {
        return this.Authenticate(this._accessControlCredentials);
    }

    private AuthenticationHeader GenerateTokenAuthorizationHeader() {
        return new AuthenticationHeader("Authorization",
                String.format("Bearer %s", this._accessControlToken.getAccessToken()));
    }
}
