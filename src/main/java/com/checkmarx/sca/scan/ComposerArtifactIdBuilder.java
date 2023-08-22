package com.checkmarx.sca.scan;

import com.checkmarx.sca.PackageManager;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.models.ArtifactId;
import com.checkmarx.sca.scan.fallbacks.ComposerFallback;
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
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;

import org.artifactory.repo.RepoPath;
import org.jfrog.security.util.Pair;
import org.slf4j.Logger;

public class ComposerArtifactIdBuilder {
    @Inject
    private Logger _logger;
    @Inject
    private ComposerFallback _composerFallback;
    private final String _baseUrl;
    private final HttpClient _httpClient;

    @Inject
    public ComposerArtifactIdBuilder(@Nonnull PluginConfiguration configuration) {
        this._baseUrl = configuration.getPropertyOrDefault(ConfigurationEntry.PACKAGIST_REPOSITORY);
        this._httpClient = HttpClient.newBuilder().version(Version.HTTP_1_1).build();
    }

    public ArtifactId generateArtifactId(@Nonnull RepoPath repoPath, @Nonnull PackageManager packageManager) {
        Pair<String, String> artifactInfo = this.parseRepoPath(repoPath);
        if (artifactInfo.getFirst() == null) {
            return new ArtifactId(packageManager.packageType(), (String) null, (String) null);
        } else {
            try {
                ArtifactId artifactId = this.requestPackageInfoFromPackagist(packageManager, (String) artifactInfo.getFirst(), (String) artifactInfo.getSecond());
                if (artifactId != null) {
                    return artifactId;
                }

                String newName = this._composerFallback.applyFallback((String) artifactInfo.getFirst());
                if (newName != null) {
                    artifactId = this.requestPackageInfoFromPackagist(packageManager, newName, (String) artifactInfo.getSecond());
                    if (artifactId != null) {
                        return artifactId;
                    }
                }

                this._logger.warn(String.format("Unable to get artifact version from Composer. Artifact path: %s", repoPath.getPath()));
            } catch (Exception var6) {
                this._logger.error(String.format("There was a problem trying to get the artifact version from Composer. Artifact path: %s", repoPath.getPath()));
                this._logger.debug("Exception", var6);
            }

            return new ArtifactId(packageManager.packageType(), (String) null, (String) null);
        }
    }

    private Pair<String, String> parseRepoPath(@Nonnull RepoPath repoPath) {
        String regex = "(?<name>.+)/commits/(?<version>.+)/.+";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(repoPath.getPath());
        if (!matcher.matches()) {
            this._logger.error(String.format("Unable to parse RepoPath from Composer. Artifact path: %s", repoPath.getPath()));
            return new Pair((Object) null, (Object) null);
        } else {
            String artifactName = matcher.group("name");
            String artifactVersion = matcher.group("version");
            if (artifactName != null && artifactVersion != null) {
                return new Pair(artifactName, artifactVersion);
            } else {
                this._logger.error(String.format("Unable to parse RepoPath from Composer. Artifact path: %s", repoPath.getPath()));
                return new Pair((Object) null, (Object) null);
            }
        }
    }

    private ArtifactId requestPackageInfoFromPackagist(@Nonnull PackageManager packageManager, @Nonnull String packageName, @Nonnull String commitReference) throws ExecutionException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(String.format("%s/p2/%s.json", this._baseUrl, packageName))).GET().build();
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient.sendAsync(request, BodyHandlers.ofString());
        HttpResponse<String> response = (HttpResponse) responseFuture.get();
        if (response.statusCode() == 200) {
            JsonElement jElement = JsonParser.parseString((String) response.body());
            JsonObject jObject = jElement.getAsJsonObject();
            JsonObject packages = jObject.getAsJsonObject("packages");
            JsonArray versions = packages.getAsJsonArray(packageName);
            Iterator var11 = versions.iterator();

            while (var11.hasNext()) {
                JsonElement vElement = (JsonElement) var11.next();
                JsonObject version = vElement.getAsJsonObject();
                JsonObject source = version.getAsJsonObject("source");
                if (source != null) {
                    String reference = source.get("reference").getAsString();
                    if (commitReference.equalsIgnoreCase(reference)) {
                        String usedVersion = version.get("version").getAsString();
                        return new ArtifactId(packageManager.packageType(), packageName, usedVersion);
                    }
                }
            }
        }

        return null;
    }
}
