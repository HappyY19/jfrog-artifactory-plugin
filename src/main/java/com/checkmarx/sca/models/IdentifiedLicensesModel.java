package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

public class IdentifiedLicensesModel {
    @SerializedName("license")
    private SoftwareLicenseModel _license;

    public SoftwareLicenseModel getLicense() {
        return this._license;
    }
}
