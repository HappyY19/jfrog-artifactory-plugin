package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

public class PackageLicense {
    @SerializedName("PackageLicense")
    private String _packageLicense;

    public PackageLicense(String licenseName) {
        this._packageLicense = licenseName;
    }

    public String getPackageLicense() {
        return this._packageLicense;
    }
}
