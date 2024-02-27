package com.checkmarx.sca.models;

public class PackageInfo {

    private String packageManager;
    private String packageName;

    private String packageVersion;

    private Double cvssScore;

    private Boolean monitored;

    public PackageInfo( ) {

    }

    public PackageInfo(String packageManager, String packageName, String packageVersion, Double cvssScore, Boolean monitored) {
        this.packageManager = packageManager;
        this.packageName = packageName;
        this.packageVersion = packageVersion;
        this.cvssScore = cvssScore;
        this.monitored = monitored;
    }

    public String getPackageManager() {
        return this.packageManager;
    }

    public void setPackageManager(String packageManager) {
        this.packageManager = packageManager;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getPackageName() {
        String[] names = this.packageName.split(":");
        if (names.length > 1) {
            return names[1];
        } else {
            return names[0];
        }
    }

    public void setPackageVersion(String packageVersion) {
        this.packageVersion = packageVersion;
    }

    public String getPackageVersion() {
        return this.packageVersion;
    }

    public void setCvssScore(Double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public Double getCvssScore() {
        return this.cvssScore;
    }

    public void setMonitored(Boolean monitored) {
        this.monitored = monitored;
    }

    public Boolean getMonitored() {
        return monitored;
    }

    @Override
    public String toString() {
        return "PackageInfo [packageManager=" + this.packageManager + ", packageName=" + this.packageName
                + ", packageVersion=" + this.packageVersion + ", cvssScore="
                + this.cvssScore.toString() + ", isMonitored=" + monitored.toString() + "]";
    }

}
