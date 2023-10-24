package com.checkmarx.sca.communication;

import com.checkmarx.sca.PackageManager;
import com.checkmarx.sca.communication.exceptions.UnexpectedResponseBodyException;
import com.checkmarx.sca.communication.exceptions.UnexpectedResponseCodeException;
import com.checkmarx.sca.communication.exceptions.UserIsNotAuthenticatedException;
import com.checkmarx.sca.communication.fallbacks.PyPiFallback;
import com.checkmarx.sca.communication.models.AuthenticationHeader;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.models.ArtifactId;
import com.checkmarx.sca.models.ArtifactInfo;
import com.checkmarx.sca.models.PackageAnalysisAggregation;
import com.checkmarx.sca.models.PackageLicensesModel;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.inject.Inject;

import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;

public class ScaHttpClient {
    private final String UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/100.0.4896.92 Safari/537.36";
    private final HttpClient _httpClient;
    private final String _apiUrl;
    @Inject
    private PyPiFallback _pyPiFallback;
    @Inject(
            optional = true
    )
    private AccessControlClient _accessControlClient;
    private Logger _logger;

    @Inject
    public ScaHttpClient(@Nonnull PluginConfiguration configuration) {
        String apiUrl = configuration.getPropertyOrDefault(ConfigurationEntry.API_URL);
        if (!apiUrl.endsWith("/")) {
            apiUrl = apiUrl + "/";
        }

        this._apiUrl = apiUrl;
        this._httpClient = HttpClient.newHttpClient();
        this._logger = configuration.getLogger();
    }

    private void logErrorResponse(String action, Map<RepoPath, HttpResponse<String>> repoPathHttpResponseMap) {
        repoPathHttpResponseMap.forEach((key, value) -> {
            if (200 != value.statusCode()) {
                this._logger.error(
                    String.format("Action, %s. " +
                                    "Repopath, %s. " +
                                    "Response, status code: %s, response body: %s",
                        action,
                        key.getPath(),
                        value.statusCode(),
                        value.body()
                    )
                );
            }
        });
    }

    private List<HttpResponse<String>> processConcurrentRequests(List<HttpRequest> requests) {
        this._logger.debug("processConcurrentRequests, begin to send HTTP requests asynchronously.");
        List<CompletableFuture<HttpResponse<String>>> responseList = requests.stream()
                .map(request -> this._httpClient.sendAsync(request, BodyHandlers.ofString()))
                .collect(Collectors.toList());
        this._logger.debug("HTTP requests send finished.");
        CompletableFuture.allOf(responseList.toArray(CompletableFuture<?>[]::new)).join();
        this._logger.debug("Waiting for all CompletableFuture to join, and get response value");
        return responseList.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList());
    }

    private List<HttpResponse<String>> concurrentGetRequests(List<URI> uris) {
        this._logger.debug("concurrentGetRequests");
        List<HttpRequest> requests = uris.stream()
                .map(HttpRequest::newBuilder)
                .map(reqBuilder -> reqBuilder
                        .header("User-Agent", this.UserAgent)
                        .header("cxorigin", this.getCxOrigin())
                        .GET()
                        .build())
                .collect(Collectors.toList());
        return processConcurrentRequests(requests);
    }

    private List<HttpResponse<String>> concurrentPostRequests(URI uri, List<String> bodies) {
        this._logger.debug("concurrentPostRequests");
        List<HttpRequest> requests = bodies.stream()
                .map(body -> HttpRequest.newBuilder(uri)
                        .header("User-Agent", this.UserAgent)
                        .header("cxorigin", this.getCxOrigin())
                        .POST(BodyPublishers.ofString(body))
                        .build()
                )
                .collect(Collectors.toList());
        return processConcurrentRequests(requests);
    }

    private Map<RepoPath, HttpResponse<String>> zipToMap(List<RepoPath> keys, List<HttpResponse<String>> values) {
        return IntStream.range(0, keys.size()).boxed()
                .collect(Collectors.toMap(keys::get, values::get));
    }

    public Map<RepoPath, ArtifactInfo> getArtifactInformationConcurrently(Map<RepoPath, ArtifactId> repoPathArtifactIdMap) {
        this._logger.debug("ScaHttpClient getArtifactInformationConcurrently start");
        List<URI> uris = repoPathArtifactIdMap.values().stream()
                .map(artifactId -> {
                    this._logger.debug(String.format("building URIs by using Artifacts, Package Type: %s, Name: %s, " +
                            "Version: %s", artifactId.PackageType, artifactId.Name, artifactId.Version));
                    return URI.create(
                        String.format("%s%s",
                            this._apiUrl,
                            String.format("public/packages/%s/%s/%s", artifactId.PackageType,
                                URLEncoder.encode(artifactId.Name, StandardCharsets.UTF_8),
                                URLEncoder.encode(artifactId.Version, StandardCharsets.UTF_8)
                            )
                        )
                    );
                })
                .collect(Collectors.toList());
        List<HttpResponse<String>> responses = concurrentGetRequests(uris);
        this._logger.debug("Finish sending");
        Map<RepoPath, HttpResponse<String>> artifactIdHttpResponseMap = this.zipToMap(
                new ArrayList<>(repoPathArtifactIdMap.keySet()),
                responses);
        logErrorResponse("getArtifactInformationConcurrently", artifactIdHttpResponseMap);
        this._logger.debug("ScaHttpClient getArtifactInformationConcurrently end, return value with response which status code is 200");
        return artifactIdHttpResponseMap.entrySet().stream()
                .filter(e -> e.getValue().statusCode() == 200)
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    e -> {
                        String body = e.getValue().body();
                        body = body.replaceAll("\\{\"identifier\":", "").replaceFirst("}", "");
                        return (ArtifactInfo) (new Gson()).fromJson(body, ArtifactInfo.class);
                    }
                ));
    }

    public Map<RepoPath, PackageAnalysisAggregation> getRiskAggregationConcurrently(Map<RepoPath, ArtifactId> repoPathArtifactIdMap) {
        this._logger.debug("ScaHttpClient getRiskAggregationConcurrently start");
        URI uri = URI.create(
                String.format("%s%s", this._apiUrl, "public/risk-aggregation/aggregated-risks"));
        List<String> bodies = repoPathArtifactIdMap.values().stream()
                .map(artifactId -> String.format("{\"packageName\":\"%s\",\"version\":\"%s\",\"packageManager\":\"%s\"}",
                        artifactId.Name, artifactId.Version, artifactId.PackageType))
                .collect(Collectors.toList());
        List<HttpResponse<String>> responses = this.concurrentPostRequests(uri, bodies);
        Map<RepoPath, HttpResponse<String>> artifactIdHttpResponseMap = this.zipToMap(
                new ArrayList<>(repoPathArtifactIdMap.keySet()),
                responses
        );
        logErrorResponse("getRiskAggregationConcurrently", artifactIdHttpResponseMap);
        Map<RepoPath, PackageAnalysisAggregation> result = artifactIdHttpResponseMap.entrySet().stream()
                .filter(e -> e.getValue().statusCode() == 200)
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    e -> {
                        Type listType = (new TypeToken<PackageAnalysisAggregation>() {}).getType();
                        return (PackageAnalysisAggregation) (new Gson()).fromJson((String) e.getValue().body(), listType);
                    }
                ));
        Map<RepoPath,PackageLicensesModel> licensesModelMap = getPackageLicenseConcurrently(repoPathArtifactIdMap);
        this._logger.debug("ScaHttpClient getRiskAggregationConcurrently end");
        this._logger.debug("combine each PackageAnalysisAggregation value and  PackageLicensesModel value");
        return result.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> {
                            PackageAnalysisAggregation packageAnalysisAggregation = e.getValue();
                            PackageLicensesModel packageLicensesModel = licensesModelMap.get(e.getKey());
                            if (packageLicensesModel.getIdentifiedLicenses() != null
                                    && !packageLicensesModel.getIdentifiedLicenses().isEmpty()) {
                                List<String> licenses = packageLicensesModel
                                        .getIdentifiedLicenses()
                                        .stream()
                                        .map((identifiedLicense) -> {
                                            return identifiedLicense.getLicense().getName();
                                        })
                                        .collect(Collectors.toList());
                                packageAnalysisAggregation.setLicenses(licenses);
                            }
                            return packageAnalysisAggregation;
                        }
                ));
    }

    public Map<RepoPath, PackageLicensesModel> getPackageLicenseConcurrently(Map<RepoPath, ArtifactId> repoPathArtifactIdMap) {
        this._logger.debug("ScaHttpClient getPackageLicenseConcurrently start");
        List<URI> uris = repoPathArtifactIdMap.values().stream()
            .map(artifactId ->
                URI.create(
                    String.format("%s%s",
                        this._apiUrl,
                        String.format("public/packages/%s/%s/versions/%s/licenses",
                                artifactId.PackageType,
                                URLEncoder.encode(artifactId.Name, StandardCharsets.UTF_8),
                                URLEncoder.encode(artifactId.Version, StandardCharsets.UTF_8)
                        )
                    )
                )
            )
            .collect(Collectors.toList());
        List<HttpResponse<String>> responses = concurrentGetRequests(uris);
        Map<RepoPath, HttpResponse<String>> artifactIdHttpResponseMap = this.zipToMap(
            new ArrayList<>(repoPathArtifactIdMap.keySet()),
            responses
        );
        logErrorResponse("getPackageLicenseConcurrently", artifactIdHttpResponseMap);
        this._logger.debug("ScaHttpClient getPackageLicenseConcurrently end,  return value with response which status code is 200");
        return artifactIdHttpResponseMap.entrySet().stream()
            .filter(e -> e.getValue().statusCode() == 200)
            .collect(Collectors.toMap(
                    Map.Entry::getKey,
                e -> {
                    Type listType = (new TypeToken<PackageLicensesModel>() {}).getType();
                    return (PackageLicensesModel) (new Gson()).fromJson((String) e.getValue().body(), listType);
                }
            ));
    }

    public ArtifactInfo getArtifactInformation(String packageType, String name, String version)
            throws ExecutionException, InterruptedException {
        HttpResponse<String> artifactResponse = this.getArtifactInfoResponse(packageType, name, version);
        if (artifactResponse.statusCode() == 404) {
            artifactResponse = this.TryToFallback(artifactResponse, packageType, name, version);
        }

        if (artifactResponse.statusCode() != 200) {
            throw new UnexpectedResponseCodeException(artifactResponse.statusCode());
        } else {
            ArtifactInfo artifactInfo;
            try {
                String body = artifactResponse.body();
                body = body.replaceAll("\\{\"identifier\":", "").replaceFirst("}", "");
                artifactInfo = (ArtifactInfo) (new Gson()).fromJson(body,
                        ArtifactInfo.class);
            } catch (Exception var7) {
                throw new UnexpectedResponseBodyException((String) artifactResponse.body());
            }

            if (artifactInfo == null) {
                throw new UnexpectedResponseBodyException("");
            } else {
                return artifactInfo;
            }
        }
    }

    public PackageAnalysisAggregation getRiskAggregationOfArtifact(String packageType, String name, String version)
            throws ExecutionException, InterruptedException {
        HttpRequest request = this.getRiskAggregationArtifactRequest(packageType, name, version);
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient
                .sendAsync(request, BodyHandlers.ofString());
        HttpResponse<String> risksResponse = responseFuture.get();
        if (risksResponse.statusCode() != 200) {
            throw new UnexpectedResponseCodeException(risksResponse.statusCode());
        } else {
            PackageAnalysisAggregation packageAnalysisAggregation;
            try {
                Type listType = (new TypeToken<PackageAnalysisAggregation>() {
                }).getType();
                packageAnalysisAggregation = (PackageAnalysisAggregation) (
                        new Gson()).fromJson((String) risksResponse.body(), listType);
            } catch (Exception var11) {
                throw new UnexpectedResponseBodyException((String) risksResponse.body());
            }

            if (packageAnalysisAggregation == null) {
                throw new UnexpectedResponseBodyException("");
            } else {
                List<String> licenses = List.of();

                try {
                    PackageLicensesModel license = this.getPackageLicenseOfArtifact(packageType, name, version);
                    if (license.getIdentifiedLicenses() != null && !license.getIdentifiedLicenses().isEmpty()) {
                        licenses = license.getIdentifiedLicenses().stream().map((identifiedLicense) -> {
                            return identifiedLicense.getLicense().getName();
                        }).collect(Collectors.toList());
                    }
                } catch (Exception var10) {
                    licenses = List.of();
                }

                packageAnalysisAggregation.setLicenses(licenses);
                return packageAnalysisAggregation;
            }
        }
    }

    public Boolean suggestPrivatePackage(ArtifactId artifactId) throws ExecutionException,
            InterruptedException, MissingResourceException {
        HttpRequest request = this.getSuggestPrivatePackageRequest(artifactId);
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient
                .sendAsync(request, BodyHandlers.ofString());
        HttpResponse<String> response = responseFuture.get();
        if (response.statusCode() != 200) {
            throw new UnexpectedResponseBodyException((String) response.body());
        } else {
            return true;
        }
    }

    private HttpRequest getRiskAggregationArtifactRequest(String packageType, String name, String version)
            throws CancelException {
        String body = String.format("{\"packageName\":\"%s\",\"version\":\"%s\",\"packageManager\":\"%s\"}",
                name, version, packageType);
        return HttpRequest.newBuilder(URI.create(
                String.format("%s%s", this._apiUrl, "public/risk-aggregation/aggregated-risks")))
                .header("content-type", "application/json")
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/100.0.4896.92 Safari/537.36")
                .header("cxorigin", this.getCxOrigin())
                .POST(BodyPublishers.ofString(body))
                .build();
    }

    private HttpRequest getLicenceArtifactRequest(
            @NotNull String packageType,
            @NotNull String name,
            @NotNull String version) throws CancelException {
        name = URLEncoder.encode(name, StandardCharsets.UTF_8);
        version = URLEncoder.encode(version, StandardCharsets.UTF_8);
        String url = String.format("public/packages/%s/%s/versions/%s/licenses", packageType, name, version);
        return HttpRequest.newBuilder(
                URI.create(String.format("%s%s", this._apiUrl, url)))
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/100.0.4896.92 Safari/537.36")
                .header("cxorigin", this.getCxOrigin())
                .GET()
                .build();
    }

    private HttpRequest getArtifactInfoRequest(
            @NotNull String packageType,
            @NotNull String name,
            @NotNull String version) {
        name = URLEncoder.encode(name, StandardCharsets.UTF_8);
        version = URLEncoder.encode(version, StandardCharsets.UTF_8);
        String artifactPath = String.format("public/packages/%s/%s/%s", packageType, name, version);
        return HttpRequest.newBuilder(
                URI.create(String.format("%s%s", this._apiUrl, artifactPath)))
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                        "(KHTML, like Gecko) Chrome/100.0.4896.92 Safari/537.36")
                .header("cxorigin", this.getCxOrigin())
                .GET()
                .build();
    }

    private HttpRequest getSuggestPrivatePackageRequest(ArtifactId artifactId) throws CancelException {
        String body = String.format("[{\"name\":\"%s\"," +
                "\"packageManager\":\"%s\"," +
                "\"version\":\"%s\"," +
                "\"origin\":\"PrivateArtifactory\"}]",
                artifactId.Name, artifactId.PackageType, artifactId.Version);
        if (this._accessControlClient == null) {
            throw new UserIsNotAuthenticatedException();
        } else {
            AuthenticationHeader<String, String> authHeader = this._accessControlClient.GetAuthorizationHeader();
            return HttpRequest.newBuilder(
                    URI.create(String.format("%s%s", this._apiUrl, "private-dependencies-repository/dependencies")))
                    .header((String) authHeader.getKey(), (String) authHeader.getValue())
                    .header("content-type", "application/json")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.92 Safari/537.36")
                    .header("cxorigin", this.getCxOrigin())
                    .POST(BodyPublishers.ofString(body))
                    .build();
        }
    }

    private HttpResponse<String> TryToFallback(
            HttpResponse<String> previousResponse,
            String packageType,
            String name,
            String version) throws ExecutionException, InterruptedException {
        String newName = null;
        if (packageType.equals(PackageManager.PYPI.packageType())) {
            newName = this._pyPiFallback.applyFallback(name);
        }

        if (newName == null) {
            throw new UnexpectedResponseCodeException(previousResponse.statusCode());
        } else {
            HttpResponse<String> artifactResponse = this.getArtifactInfoResponse(packageType, newName, version);
            if (artifactResponse.statusCode() == 404) {
                throw new UnexpectedResponseCodeException(artifactResponse.statusCode());
            } else {
                return artifactResponse;
            }
        }
    }

    private HttpResponse<String> TryToFallbackLicense(
            HttpResponse<String> previousResponse,
            String packageType,
            String name,
            String version) throws ExecutionException, InterruptedException {
        String newName = null;
        if (packageType.equals(PackageManager.PYPI.packageType())) {
            newName = this._pyPiFallback.applyFallback(name);
        }

        if (newName == null) {
            throw new UnexpectedResponseCodeException(previousResponse.statusCode());
        } else {
            HttpRequest artifactRequest = this.getLicenceArtifactRequest(packageType, newName, version);
            HttpResponse<String> artifactResponse = this._httpClient
                    .sendAsync(artifactRequest, BodyHandlers.ofString()).get();
            if (artifactResponse.statusCode() == 404) {
                throw new UnexpectedResponseCodeException(artifactResponse.statusCode());
            } else {
                return artifactResponse;
            }
        }
    }

    private HttpResponse<String> getArtifactInfoResponse(String packageType, String name, String version)
            throws ExecutionException, InterruptedException {
        HttpRequest request = this.getArtifactInfoRequest(packageType, name, version);
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient
                .sendAsync(request, BodyHandlers.ofString());
        return responseFuture.get();
    }

    public PackageLicensesModel getPackageLicenseOfArtifact(String packageType, String name, String version)
            throws ExecutionException, InterruptedException {
        HttpRequest request = this.getLicenceArtifactRequest(packageType, name, version);
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient
                .sendAsync(request, BodyHandlers.ofString());
        HttpResponse<String> licenseResponse = responseFuture.get();
        if (licenseResponse.statusCode() == 404) {
            licenseResponse = this.TryToFallbackLicense(licenseResponse, packageType, name, version);
        }

        if (licenseResponse.statusCode() != 200) {
            throw new UnexpectedResponseCodeException(licenseResponse.statusCode());
        } else {
            PackageLicensesModel packageAnalysisAggregation;
            try {
                Type listType = (new TypeToken<PackageLicensesModel>() {
                }).getType();
                packageAnalysisAggregation = (PackageLicensesModel) (new Gson())
                        .fromJson((String) licenseResponse.body(), listType);
            } catch (Exception var9) {
                throw new UnexpectedResponseBodyException((String) licenseResponse.body());
            }

            if (packageAnalysisAggregation == null) {
                throw new UnexpectedResponseBodyException("");
            } else {
                return packageAnalysisAggregation;
            }
        }
    }

    private String getCxOrigin() {
        Package p = this.getClass().getPackage();
        String version = p.getImplementationVersion() != null ? p.getImplementationVersion() : "1.0.0";
        return String.format("JFrog %s", version);
    }
}
