package com.checkmarx.sca.models;

import com.google.gson.annotations.SerializedName;

public class ArtifactInfo {
    @SerializedName("id")
    private ArtifactId _id;
    @SerializedName("name")
    private String _name;
    @SerializedName("version")
    private String _version;
    @SerializedName("type")
    private String _type;
    @SerializedName("releaseDate")
    private String _releaseDate;
    @SerializedName("description")
    private String _description;
    @SerializedName("repositoryUrl")
    private String _repositoryUrl;
    @SerializedName("binaryUrl")
    private String _binaryUrl;
    @SerializedName("projectUrl")
    private String _projectUrl;
    @SerializedName("bugsUrl")
    private Object bugsUrl;
    @SerializedName("sourceUrl")
    private String _sourceUrl;
    @SerializedName("projectHomePage")
    private String _projectHomePage;
    @SerializedName("homePage")
    private String _homePage;
    @SerializedName("license")
    private String _license;
    @SerializedName("summary")
    private String _summary;
    @SerializedName("url")
    private String _url;
    @SerializedName("owner")
    private String _owner;

    public ArtifactInfo() {
    }

    public ArtifactId getId() {
        return this._id;
    }

    public String getPackageType() {
        return this._type;
    }

    public String getName() {
        return this._name;
    }

    public String getVersion() {
        return this._version;
    }
}
