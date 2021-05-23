package kr.jclab.javautils.pluginloader;

import java.io.File;
import java.util.jar.JarFile;

public class JarFileEntry implements Cloneable {
    private final File file;
    private final JarFile jarFile;
    private final String baseUrl;

    public JarFileEntry(File file, JarFile jarFile) {
        this.file = file;
        this.jarFile = jarFile;
        this.baseUrl = "jar:" + file.toURI().toString() + "!";
    }

    public File getFile() {
        return file;
    }

    public JarFile getJarFile() {
        return jarFile;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    @Override
    public JarFileEntry clone() {
        return new JarFileEntry(this.file, this.jarFile);
    }
}
