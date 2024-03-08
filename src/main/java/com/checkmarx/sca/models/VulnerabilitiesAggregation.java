package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

public class VulnerabilitiesAggregation {
    @SerializedName("vulnerabilitiesCount")
    private int _vulnerabilitiesCount;
    @SerializedName("maxRiskSeverity")
    private String _maxRiskSeverity;
    @SerializedName("maxRiskScore")
    private double _maxRiskScore;
    @SerializedName("highRiskCount")
    private int _highRiskCount;
    @SerializedName("mediumRiskCount")
    private int _mediumRiskCount;
    @SerializedName("lowRiskCount")
    private int _lowRiskCount;

    public int getVulnerabilitiesCount() {
        return this._vulnerabilitiesCount;
    }

    public String getMaxRiskSeverity() {
        return this._maxRiskSeverity;
    }

    public double getMaxRiskScore() {
        return this._maxRiskScore;
    }

    public int getHighRiskCount() {
        return this._highRiskCount;
    }

    public int getMediumRiskCount() {
        return this._mediumRiskCount;
    }

    public int getLowRiskCount() {
        return this._lowRiskCount;
    }
}
