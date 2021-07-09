package kr.jclab.javautils.pluginloader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

public class JarPluginClassLoader extends SecureClassLoader implements Closeable {
    public static class JarEntryWithFile {
        public final JarFileEntry fileEntry;
        public final JarEntry jarEntry;

        public JarEntryWithFile(JarFileEntry fileEntry, JarEntry jarEntry) {
            this.fileEntry = fileEntry;
            this.jarEntry = jarEntry;
        }
    }

    private final Logger logger;
    private final JarVerifier jarVerifier;
    private final List<JarFileEntry> jarFiles;

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

    public JarPluginClassLoader(List<File> files, ClassLoader parent, JarVerifier jarVerifier, AccessControlContext acc, Logger logger) throws IOException, SecurityException {
        super(parent);
        checkSecurityCreateClassLoader();

        if (logger == null) {
            logger = LoggerFactory.getLogger(this.getClass());
        }
        this.logger = logger;
        this.jarVerifier = jarVerifier;
        this.acc = acc;

        ArrayList<JarFileEntry> jarFiles = new ArrayList<>();
        jarFiles.ensureCapacity(files.size());
        for (File file : files) {
            JarFile jarFile = new JarFile(file);
            jarVerifier.verify(jarFile);
            jarFiles.add(new JarFileEntry(file, jarFile));
        }
        this.jarFiles = Collections.unmodifiableList(jarFiles);

        this.loaders = new LinkedList<>();
        this.loaders.add(new LocalLoader());
        this.loaders.add(new ParentLoader());
    }

    public List<JarFileEntry> getJarFiles() {
        return this.jarFiles.stream()
                .map(JarFileEntry::clone)
                .collect(Collectors.toList());
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

    private JarFileEntry findJarFileEntryByUrl(URL url) throws MalformedURLException {
        for (JarFileEntry entry : this.jarFiles) {
            URL entryUrl = entry.getFile().toURI().toURL();
            if (url.equals(entryUrl)) {
                return entry;
            }
        }
        return null;
    }

	@Override
	public URL getResource(String name) {
		Objects.requireNonNull(name);
		URL url = findResource(name);
		if (url == null) {
			url = super.getResource(name);
		}
		return url;
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
                JarFileEntry jarFileEntry = this.findJarFileEntryByUrl(jarURLConnection.getJarFileURL());
                if (jarFileEntry != null) {
                    JarEntry jarEntry = jarFileEntry.getJarFile().getJarEntry(jarURLConnection.getEntryName());
                    if (jarEntry == null) return null;
                    InputStream inputStream = jarFileEntry.getJarFile().getInputStream(jarEntry);
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
                            JarEntryWithFile jarEntry = JarPluginClassLoader.this.findJarEntryByPath(name);
                            if (jarEntry == null) return null;
							String absName = name;
							if (!absName.startsWith("/")) absName = "/" + absName;
							return new URL(jarEntry.fileEntry.getBaseUrl() + absName);
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

    public static JarPluginClassLoader newInstance(final List<File> files, final ClassLoader parent, final JarVerifier jarVerifier) throws IOException, SecurityException {
        // Save the caller's context
        final AccessControlContext acc = AccessController.getContext();
        // Need a privileged block to create the class loader
        try {
            JarPluginClassLoader ucl = AccessController.doPrivileged(
                    new PrivilegedAction<JarPluginClassLoader>() {
                        public JarPluginClassLoader run() {
                            try {
                                return new JarPluginClassLoader(files, parent, jarVerifier, acc, null);
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

    private JarEntryWithFile findJarEntryByPath(String name) {
        for (JarFileEntry entry : this.jarFiles) {
            JarEntry jarEntry = entry.getJarFile().getJarEntry(name);
            if (jarEntry != null) return new JarEntryWithFile(entry, jarEntry);
        }
        return null;
    }

    private JarEntryWithFile findJarEntry(String className) {
        className = this.formatClassName(className);
        return this.findJarEntryByPath(className);
    }

    private InputStream loadJarEntryInputStream(JarEntryWithFile jarEntry) throws IOException {
        return jarEntry.fileEntry.getJarFile().getInputStream(jarEntry.jarEntry);
    }

    private byte[] loadJarEntryContent(JarEntryWithFile jarEntry) throws IOException {
        byte[] buffer = new byte[(int)jarEntry.jarEntry.getSize()];
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
            JarEntryWithFile jarEntry = JarPluginClassLoader.this.findJarEntry(className);
            if (jarEntry == null) return null;
            try {
                byte[] classContent = JarPluginClassLoader.this.loadJarEntryContent(jarEntry);
                ProtectionDomain protectionDomain = JarPluginClassLoader.this.getProtectionDomain(className, jarEntry.fileEntry.getJarFile(), jarEntry.jarEntry);
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

    protected ProtectionDomain getProtectionDomain(String className, JarFile jarFile, JarEntry jarEntry) {
        return null;
    }
}
