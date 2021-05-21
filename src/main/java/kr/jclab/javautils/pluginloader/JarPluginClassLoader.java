package kr.jclab.javautils.pluginloader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarPluginClassLoader extends SecureClassLoader implements Closeable {
    private final Logger logger;
    private final File file;
    private final JarFile jarFile;
    private final String baseUrl;

    /**
     * The context to be used when loading classes and resources
     */
    private final AccessControlContext acc;

    private boolean lock = false;
    private final LinkedList<ProxyClassLoader> loaders;

    private char classNameReplacementChar = 0;
    protected final Map<String, Class<?>> classes = Collections.synchronizedMap(new HashMap<>());
    private final WeakHashMap<Closeable,Void> closeables = new WeakHashMap<>();

    private final ParentLoader parentLoader = new ParentLoader();
    private final LocalLoader localLoader = new LocalLoader();

    private static void checkSecurityCreateClassLoader() {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
    }

    public JarPluginClassLoader(File file, ClassLoader parent, AccessControlContext acc, Logger logger) throws IOException {
        super(parent);
        checkSecurityCreateClassLoader();

        if (logger == null) {
            logger = LoggerFactory.getLogger(this.getClass());
        }
        this.logger = logger;
        this.acc = acc;
        this.file = file;
        this.jarFile = new JarFile(file);
        this.baseUrl = "jar:" + file.toURI().toString() + "!";

        this.loaders = new LinkedList<>();
        this.loaders.add(new LocalLoader());
        this.loaders.add(new ParentLoader());
    }

    public JarFile getJarFile() {
        return jarFile;
    }

    public File getFile() {
        return file;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public final void lock() {
        this.lock = true;
        this.parentLoader.lock();
        this.localLoader.lock();
    }

    public final boolean isLocked() {
        return lock;
    }

    public void addLoader(ProxyClassLoader loader) {
        if (this.lock) throw new IllegalStateException("locked");
        this.loaders.add(loader);
        Collections.sort(this.loaders);
    }

    public final ParentLoader getParentLoader() {
        return parentLoader;
    }

    public final LocalLoader getLocalLoader() {
        return localLoader;
    }

    public InputStream getResourceAsStream(String name) {
        URL url = getResource(name);
        try {
            if (url == null) {
                return null;
            }
            URLConnection urlConnection = url.openConnection();
            if (urlConnection instanceof JarURLConnection) {
                JarURLConnection jarURLConnection = (JarURLConnection) urlConnection;
                if (jarURLConnection.getJarFileURL().equals(this.file.toURI().toURL())) {
                    JarEntry jarEntry = this.jarFile.getJarEntry(jarURLConnection.getEntryName());
                    if (jarEntry == null) return null;
                    InputStream inputStream = this.jarFile.getInputStream(jarEntry);
                    synchronized (closeables) {
                        closeables.put(inputStream, null);
                    }
                    return inputStream;
                }
            }
            return null;
        } catch (IOException e) {
            logger.warn("getResourceAsStream", e);
            return null;
        }
    }

    @Override
    public void close() throws IOException {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkPermission(new RuntimePermission("closeClassLoader"));
        }
        List<IOException> errors = new LinkedList<>();

        for (ProxyClassLoader loader : this.loaders) {
            try {
                loader.close();
            } catch (IOException e) {
                errors.add(e);
            }
        }

        // now close any remaining streams.
        synchronized (this.closeables) {
            Set<Closeable> keys = this.closeables.keySet();
            for (Closeable c : keys) {
                try {
                    c.close();
                } catch (IOException ioex) {
                    errors.add(ioex);
                }
            }
            this.closeables.clear();
        }

        if (errors.isEmpty()) {
            return;
        }

        IOException firstex = errors.remove(0);

        // Suppress any remaining exceptions

        for (IOException error: errors) {
            firstex.addSuppressed(error);
        }
        throw firstex;
    }

    @Override
    protected URL findResource(String name) {
        URL url = AccessController.doPrivileged(
                new PrivilegedAction<URL>() {
                    public URL run() {
                        try {
                            return new URL(JarPluginClassLoader.this.baseUrl + name);
                        } catch (MalformedURLException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }, acc);
        return url;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> clazz;
            ClassNotFoundException lastException = null;
            for (ProxyClassLoader loader : this.loaders) {
                try {
                    clazz = loader.loadClass(name, resolve);
                    if (clazz != null) {
                        this.logger.debug("class loaded from " + loader.getClass().getSimpleName() + ": " + name);
                        if (resolve) {
                            this.resolveClass(clazz);
                        }
                        return clazz;
                    }
                } catch (ClassNotFoundException e) {
                    lastException = e;
                }
            }
            this.logger.info("class not found: " + name);
            if (lastException == null) {
                lastException = new ClassNotFoundException("class not found");
            }
            throw lastException;
        }
    }

    protected String formatClassName(String className) {
        className = className.replace('/', '~');
        if (this.classNameReplacementChar == 0) {
            className = className.replace('.', '/') + ".class";
        } else {
            className = className.replace('.', this.classNameReplacementChar) + ".class";
        }
        className = className.replace('~', '/');
        return className;
    }

    public char getClassNameReplacementChar() {
        return this.classNameReplacementChar;
    }

    public void setClassNameReplacementChar(char classNameReplacementChar) {
        this.classNameReplacementChar = classNameReplacementChar;
    }

    public static JarPluginClassLoader newInstance(final File file, final ClassLoader parent) throws IOException {
        // Save the caller's context
        final AccessControlContext acc = AccessController.getContext();
        // Need a privileged block to create the class loader
        try {
            JarPluginClassLoader ucl = AccessController.doPrivileged(
                    new PrivilegedAction<JarPluginClassLoader>() {
                        public JarPluginClassLoader run() {
                            try {
                                return new JarPluginClassLoader(file, parent, acc, null);
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    });
            return ucl;
        } catch (RuntimeException e) {
            if (e.getCause() != null && e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            }
            throw e;
        }
    }

    private JarEntry findJarEntry(String className) {
        className = this.formatClassName(className);
        return this.jarFile.getJarEntry(className);
    }

    private InputStream loadJarEntryInputStream(JarEntry jarEntry) throws IOException {
        return this.jarFile.getInputStream(jarEntry);
    }

    private byte[] loadJarEntryContent(JarEntry jarEntry) throws IOException {
        byte[] buffer = new byte[(int)jarEntry.getSize()];
        int position = 0;
        int readlen;

        try (InputStream inputStream = loadJarEntryInputStream(jarEntry)) {
            while ((readlen = inputStream.read(buffer, position, buffer.length - position)) > 0) {
                position += readlen;
            }
            if (position != buffer.length) {
                throw new IOException("class file read failed");
            }
        }

        return buffer;
    }

    public final class LocalLoader extends ProxyClassLoader {
        @Override
        public final Class<?> loadClass(String className, boolean resolve) throws ClassNotFoundException {
            Class<?> clazz = classes.get(className);
            if (clazz != null) return clazz;
            JarEntry jarEntry = JarPluginClassLoader.this.findJarEntry(className);
            if (jarEntry == null) return null;
            try {
                byte[] classContent = JarPluginClassLoader.this.loadJarEntryContent(jarEntry);
                ProtectionDomain protectionDomain = JarPluginClassLoader.this.getProtectionDomain(className, jarEntry);
                clazz = JarPluginClassLoader.this.defineClass(className, classContent, 0, classContent.length, protectionDomain);
                if (clazz.getPackage() == null) {
                    int lastDotIndex = className.lastIndexOf('.');
                    String packageName = lastDotIndex >= 0 ? className.substring(0, lastDotIndex) : "";
                    JarPluginClassLoader.this.definePackage(packageName, (String)null, (String)null, (String)null, (String)null, (String)null, (String)null, (URL)null);
                }
                return clazz;
            } catch (Throwable e) {
                throw new ClassNotFoundException("nested", e);
            }
        }
    }

    public final class ParentLoader extends ProxyClassLoader {
        @Override
        public Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            return JarPluginClassLoader.this.getParent().loadClass(name);
        }
    }

    protected ProtectionDomain getProtectionDomain(String className, JarEntry jarEntry) {
        return null;
    }
}
