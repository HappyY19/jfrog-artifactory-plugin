package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

public class SoftwareLicenseModel {
    @SerializedName("name")
    private String _name;

    public SoftwareLicenseModel() {
    }

    public String getName() {
        return this._name;
    }
}
