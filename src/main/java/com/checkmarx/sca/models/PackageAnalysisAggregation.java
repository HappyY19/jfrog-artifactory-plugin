package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class PackageAnalysisAggregation {
    @SerializedName("packageVulnerabilitiesAggregation")
    private VulnerabilitiesAggregation _vulnerabilitiesAggregation;
    @SerializedName("packageLicenses")
    private List<String> _licenses;

    public VulnerabilitiesAggregation getVulnerabilitiesAggregation() {
        return this._vulnerabilitiesAggregation;
    }

    public List<String> getLicenses() {
        return this._licenses;
    }

    public void setLicenses(List<String> licenses) {
        this._licenses = licenses;
    }
}
