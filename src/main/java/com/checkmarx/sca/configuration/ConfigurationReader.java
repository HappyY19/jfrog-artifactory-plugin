package com.checkmarx.sca.configuration;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import javax.annotation.Nonnull;

import org.slf4j.Logger;

public final class ConfigurationReader {
    private static final String CONFIGURATIONS_FILE = "cxsca-security-plugin.properties";

    public static PluginConfiguration loadConfiguration(@Nonnull File pluginsDirectory, @Nonnull Logger logger) throws IOException {
        if (!pluginsDirectory.exists()) {
            throw new IOException(String.format("Directory '%s' not found", pluginsDirectory.getAbsolutePath()));
        } else {
            File propertyFile = new File(pluginsDirectory, "cxsca-security-plugin.properties");
            if (!propertyFile.exists()) {
                throw new IOException(String.format("File '%s' not found", propertyFile.getAbsolutePath()));
            } else {
                Properties configuration = new Properties();
                FileInputStream fis = new FileInputStream(propertyFile);

                try {
                    configuration.load(fis);
                } catch (Throwable var8) {
                    try {
                        fis.close();
                    } catch (Throwable var7) {
                        var8.addSuppressed(var7);
                    }

                    throw var8;
                }

                fis.close();
                return new PluginConfiguration(configuration, logger);
            }
        }
    }
}
