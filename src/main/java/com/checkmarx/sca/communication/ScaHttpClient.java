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
import java.util.List;
import java.util.MissingResourceException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.jetbrains.annotations.NotNull;

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

    @Inject
    public ScaHttpClient(@Nonnull PluginConfiguration configuration) {
        String apiUrl = configuration.getPropertyOrDefault(ConfigurationEntry.API_URL);
        if (!apiUrl.endsWith("/")) {
            apiUrl = apiUrl + "/";
        }

        this._apiUrl = apiUrl;
        this._httpClient = HttpClient.newHttpClient();
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
                artifactInfo = (ArtifactInfo) (new Gson()).fromJson((String) artifactResponse.body(),
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
        HttpResponse<String> risksResponse = (HttpResponse) responseFuture.get();
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
                        licenses = (List) license.getIdentifiedLicenses().stream().map((identifiedLicense) -> {
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
        HttpResponse<String> response = (HttpResponse) responseFuture.get();
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
            HttpResponse<String> artifactResponse = (HttpResponse) this._httpClient
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
        return (HttpResponse) responseFuture.get();
    }

    private PackageLicensesModel getPackageLicenseOfArtifact(String packageType, String name, String version)
            throws ExecutionException, InterruptedException {
        HttpRequest request = this.getLicenceArtifactRequest(packageType, name, version);
        CompletableFuture<HttpResponse<String>> responseFuture = this._httpClient
                .sendAsync(request, BodyHandlers.ofString());
        HttpResponse<String> licenseResponse = (HttpResponse) responseFuture.get();
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
