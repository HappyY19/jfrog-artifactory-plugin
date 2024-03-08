package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class PackageLicensesModel {
    @SerializedName("identifiedLicenses")
    private List<IdentifiedLicensesModel> _identifiedLicenses;

    public PackageLicensesModel() {
    }

    public List<IdentifiedLicensesModel> getIdentifiedLicenses() {
        return this._identifiedLicenses;
    }
}