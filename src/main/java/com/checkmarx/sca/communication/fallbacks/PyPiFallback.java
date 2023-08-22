package com.checkmarx.sca.communication.fallbacks;

public class PyPiFallback {
    public PyPiFallback() {
    }

    public String applyFallback(String name) {
        String newName = null;
        if (name.contains("-")) {
            newName = name.replaceAll("-", "_");
        } else if (name.contains("_")) {
            newName = name.replaceAll("_", "-");
        }

        return newName;
    }
}
