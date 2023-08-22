package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

public class ArtifactId {
    public final transient String Name;
    public final transient String Version;
    public final transient String PackageType;
    @SerializedName("identifier")
    private String _identifier;

    public ArtifactId(String packageType, String name, String version) {
        this.Name = name;
        this.Version = version;
        this.PackageType = packageType;
    }

    public boolean isInvalid() {
        return this.Name == null || this.Name.trim().isEmpty() || this.Version == null || this.Version.trim().isEmpty() || this.PackageType == null || this.PackageType.trim().isEmpty();
    }

    public String getIdentifier() {
        return this._identifier;
    }
}
