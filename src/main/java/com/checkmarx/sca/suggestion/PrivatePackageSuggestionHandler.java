package com.checkmarx.sca.suggestion;

import com.checkmarx.sca.PackageManager;
import com.checkmarx.sca.communication.ScaHttpClient;
import com.checkmarx.sca.communication.exceptions.UnexpectedResponseCodeException;
import com.checkmarx.sca.models.ArtifactId;
import com.checkmarx.sca.scan.ArtifactIdBuilder;
import com.google.inject.Inject;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.md.Properties;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.slf4j.Logger;

public class PrivatePackageSuggestionHandler {
    public static final String SUGGESTED_KEY = "CxSCA.PrivatePackageSuggested";
    @Inject
    private Logger _logger;
    @Inject
    private ScaHttpClient _scaHttpClient;
    @Inject
    private ArtifactIdBuilder _artifactIdBuilder;
    private final Repositories _repositories;
    private final boolean _noAuthConfiguration;

    @Inject
    public PrivatePackageSuggestionHandler(@Nonnull Repositories repositories, boolean hasAuthConfiguration) {
        this._repositories = repositories;
        this._noAuthConfiguration = !hasAuthConfiguration;
    }

    public void suggestPrivatePackage(@Nonnull RepoPath repoPath,
                                      @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) throws CancelException {
        if (!this._noAuthConfiguration) {
            boolean isSuggested = this._repositories
                    .hasProperty(repoPath, "CxSCA.PrivatePackageSuggested");
            if (!isSuggested) {
                if (nonVirtualRepoPaths.contains(repoPath)) {
                    String repositoryKey = repoPath.getRepoKey();
                    RepositoryConfiguration repoConfiguration = this._repositories
                            .getRepositoryConfiguration(repositoryKey);

                    try {
                        String packageType = repoConfiguration.getPackageType();
                        PackageManager packageManager = PackageManager.GetPackageType(packageType);
                        FileLayoutInfo fileLayoutInfo = this._repositories.getLayoutInfo(repoPath);
                        ArtifactId artifactId = this._artifactIdBuilder
                                .getArtifactId(fileLayoutInfo, repoPath, packageManager);
                        if (artifactId.isInvalid()) {
                            this._logger.error(String.format("The artifact id was not built correctly. " +
                                    "PackageType: %s, Name: %s, Version: %s",
                                    artifactId.PackageType, artifactId.Name, artifactId.Version));
                            return;
                        }

                        Boolean succeeded = this.performSuggestion(artifactId);
                        if (succeeded && !this.markResourceAsSuggested(repoPath)) {
                            this._logger.info("Failed to mark the package as suggested.");
                        }
                    } catch (Exception var11) {
                        this._logger.error(String.format("Exception Message: %s. Artifact Name: %s.",
                                var11.getMessage(), repoPath.getName()), var11);
                    }

                }
            }
        }
    }

    private Boolean performSuggestion(ArtifactId artifactId) {
        try {
            Boolean output = this._scaHttpClient.suggestPrivatePackage(artifactId);
            this._logger.debug("The package was suggested as potential private.");
            return output;
        } catch (UnexpectedResponseCodeException | InterruptedException | ExecutionException var3) {
            this._logger.warn("Failed to publish private package suggestion", var3);
            return false;
        }
    }

    private boolean markResourceAsSuggested(RepoPath repoPath) {
        Properties props = this._repositories
                .setProperty(repoPath, "CxSCA.PrivatePackageSuggested", new String[]{"true"});
        return props.containsKey("CxSCA.PrivatePackageSuggested");
    }
}
