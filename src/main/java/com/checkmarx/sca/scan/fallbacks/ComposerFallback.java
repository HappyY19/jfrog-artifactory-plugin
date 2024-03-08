package com.checkmarx.sca.scan.fallbacks;

import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Inject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Iterator;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nonnull;

import org.slf4j.Logger;

public class ComposerFallback {
    @Inject
    private Logger _logger;
    private final String _baseUrl;
    private final HttpClient _httpClient;

    @Inject
    public ComposerFallback(@Nonnull PluginConfiguration configuration) {
        this._baseUrl = configuration.getPropertyOrDefault(ConfigurationEntry.PACKAGIST_REPOSITORY);
        this._httpClient = HttpClient.newBuilder().version(Version.HTTP_1_1).build();
    }

    public String applyFallback(String name) {
        this._logger.debug("Using Composer Fallback System.");
        String[] arrOfStr = name.split("/", 2);
        if (arrOfStr.length != 2) {
            return null;
        } else {
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(String.format("%s/search.json?q=%s", this._baseUrl, arrOfStr[1]))).GET().build();
                CompletableFuture responseFuture = this._httpClient.sendAsync(request, BodyHandlers.ofString());
                HttpResponse response = (HttpResponse) responseFuture.get();
                if (response.statusCode() == 200) {
                    JsonElement jElement = JsonParser.parseString((String) response.body());
                    JsonObject jObject = jElement.getAsJsonObject();
                    JsonArray results = jObject.getAsJsonArray("results");
                    Iterator var9 = results.iterator();

                    while (var9.hasNext()) {
                        JsonElement result = (JsonElement) var9.next();
                        JsonObject packageData = result.getAsJsonObject();
                        String repository = packageData.get("repository").getAsString();
                        if (repository != null && repository.contains(name)) {
                            this._logger.debug("Composer fallback found new name for the artifact.");
                            return packageData.get("name").getAsString();
                        }
                    }
                }
            } catch (Exception var13) {
                this._logger.debug("Exception", var13);
            }

            this._logger.debug("Composer fallback couldn't find any alternative name for the artifact.");
            return null;
        }
    }
}
