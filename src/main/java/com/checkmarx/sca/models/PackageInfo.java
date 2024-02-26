package com.checkmarx.sca.models;

public class PackageInfo {

    private String packageName;

    private String packageVersion;

    private Double cvssScore;

    public PackageInfo( ) {

    }

    public PackageInfo(String packageName, String packageVersion, Double cvssScore) {
        this.packageName = packageName;
        this.packageVersion = packageVersion;
        this.cvssScore = cvssScore;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getPackageName() {
        return this.packageName;
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

    @Override
    public String toString() {
        return "PackageInfo [packageName=" + this.packageName + ", packageVersion=" + this.packageVersion + ", cvssScore="
                + this.cvssScore.toString() + "]";
    }

}