package com.checkmarx.sca.scan;

import com.checkmarx.sca.PackageManager;
import com.checkmarx.sca.models.ArtifactId;
import com.google.inject.Inject;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;

import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.slf4j.Logger;

public class ArtifactIdBuilder {
    @Inject
    private Logger _logger;
    @Inject
    private ComposerArtifactIdBuilder _composerArtifactIdBuilder;

    public ArtifactIdBuilder() {
    }

    public ArtifactId getArtifactId(@Nonnull FileLayoutInfo fileLayoutInfo,
                                    @Nonnull RepoPath repoPath,
                                    @Nonnull PackageManager packageManager) {
        String revision = fileLayoutInfo.getBaseRevision();
        String name = fileLayoutInfo.getModule();
        List<String> validFileLayouts = List.of(PackageManager.MAVEN.key(), PackageManager.GRADLE.key());
        if (validFileLayouts.contains(packageManager.key())) {
            return this.getArtifactIdOfValidLayout(fileLayoutInfo, packageManager, name, revision);
        } else {
            switch (packageManager) {
                case NOTSUPPORTED:
                    return new ArtifactId(packageManager.packageType(), name, revision);
                case COMPOSER:
                    return this._composerArtifactIdBuilder.generateArtifactId(repoPath, packageManager);
                default:
                    return this.tryToUseRegex(repoPath, packageManager);
            }
        }
    }

    private ArtifactId getArtifactIdOfValidLayout(FileLayoutInfo fileLayoutInfo,
                                                  PackageManager packageManager,
                                                  String name,
                                                  String revision) {
        String organization = fileLayoutInfo.getOrganization();
        String fileIntegrationRevision = fileLayoutInfo.getFileIntegrationRevision();
        name = String.format("%s:%s", organization, name);
        if (fileIntegrationRevision != null) {
            revision = String.format("%s-%s", revision, fileIntegrationRevision);
        }

        return new ArtifactId(packageManager.packageType(), name, revision);
    }

    private ArtifactId tryToUseRegex(RepoPath repoPath, PackageManager packageManager) {
        try {
            String regex;
            switch (packageManager) {
                case NPM:
                    regex = "(?<name>.+)\\/-\\/.+-(?<version>\\d+\\.\\d+\\.\\d+.*)\\.tgz";
                    break;
                case PYPI:
                    regex = ".+/(?<name>.+)-(?<version>\\d+(?:\\.[A-Za-z0-9]+)*).*\\.(?:whl|egg|zip|tar\\.gz)";
                    break;
                case NUGET:
                    regex = "(?<name>.*?)\\.(?<version>(?:\\.?[0-9]+){3,}(?:[-a-z]+)?)\\.nupkg";
                    break;
                case BOWER:
                    regex = ".*/(?<name>.+)-v?(?<version>\\d(?:\\.[A-Za-z0-9]+)*).*tar\\.gz";
                    break;
                case IVY:
                case SBT:
                    return this.parseMavenRepoPath(repoPath, packageManager);
                case COCOAPODS:
                    regex = ".*\\/(?<name>.+)-v?(?<version>\\d(?:\\.[A-Za-z0-9]+)*).*(?:zip|tar\\.gz)";
                    ArtifactId tmpId = this.parseRepoPath(repoPath.getPath(), packageManager, regex);
                    if (tmpId.isInvalid()) {
                        return tmpId;
                    }

                    String name = String.format("%s:%s", tmpId.Name, tmpId.Name);
                    return new ArtifactId(packageManager.packageType(), name, tmpId.Version);
                case GO:
                    String path = repoPath.getPath();
                    path = path.replaceAll("(\\+incompatible)?(\\.mod|\\.info|\\.zip)", "");
                    regex = "(?<name>.*?)\\/@v\\/(?<version>.*)";
                    return this.parseRepoPath(path, packageManager, regex);
                default:
                    this._logger.info(String.format("Trying to parse RepoPath through regex but packageType " +
                            "is not supported. PackageType: %s, Artifact Name: %s",
                            packageManager.packageType(),
                            repoPath.getName()));
                    this._logger.debug(String.format("Path not supported by regex. Artifact path: %s",
                            repoPath.getPath()));
                    return new ArtifactId(packageManager.packageType(), (String) null, (String) null);
            }

            return this.parseRepoPath(repoPath.getPath(), packageManager, regex);
        } catch (Exception var7) {
            this._logger.error(String.format("There was a problem trying to use a Regex to parse " +
                    "the artifact path. Artifact path: %s", repoPath.getPath()));
            this._logger.debug("Exception", var7);
            return new ArtifactId(packageManager.packageType(), (String) null, (String) null);
        }
    }

    public ArtifactId parseRepoPath(String path, PackageManager packageManager, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(path);
        if (matcher.matches()) {
            String name = matcher.group("name");
            String version = matcher.group("version");
            this.LogPackageDebug(path, packageManager, name, version);
            return new ArtifactId(packageManager.packageType(), name, version);
        } else {
            return new ArtifactId(packageManager.packageType(), (String) null, (String) null);
        }
    }

    private ArtifactId parseMavenRepoPath(RepoPath repoPath, PackageManager packageManager) {
        Pattern pattern = Pattern.compile("(?<packagePath>.+)/(?<version>\\d+(?:\\.[A-Za-z0-9]+)*).*");
        Matcher matcher = pattern.matcher(repoPath.getPath());
        if (matcher.matches()) {
            String packagePath = matcher.group("packagePath");
            String version = matcher.group("version");
            String[] packagePathArray = packagePath.split("/");
            String organisation = String.join(".",
                    (CharSequence[]) Arrays.copyOfRange(packagePathArray, 0, packagePathArray.length - 1));
            String packageName = packagePathArray[packagePathArray.length - 1];
            String name = String.format("%s:%s", organisation, packageName);
            this.LogPackageDebug(repoPath.getPath(), packageManager, name, version);
            return new ArtifactId(packageManager.packageType(), name, version);
        } else {
            return new ArtifactId(packageManager.packageType(), (String) null, (String) null);
        }
    }

    private void LogPackageDebug(String repoPath, PackageManager packageManager, String name, String version) {
        this._logger.debug(String.format("PackageManager: %s", packageManager.key()));
        this._logger.debug(String.format("RepoPath: %s", repoPath));
        this._logger.debug(String.format("Parsed name: %s", name));
        this._logger.debug(String.format("Parsed version: %s", version));
    }
}
