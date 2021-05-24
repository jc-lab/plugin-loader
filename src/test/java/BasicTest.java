import kr.jclab.javautils.pluginloader.JarPluginClassLoader;
import kr.jclab.javautils.pluginloader.JarVerificationContext;
import kr.jclab.javautils.pluginloader.JarVerificationHandler;
import kr.jclab.javautils.pluginloader.JarVerifier;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class BasicTest {
    public static class DefaultVerificationHandler implements JarVerificationHandler {
        private final boolean initialVerified;

        public DefaultVerificationHandler(boolean initialVerified) {
            this.initialVerified = initialVerified;
        }

        @Override
        public void start(JarVerificationContext context) {
            context.setVerified(this.initialVerified);
        }

        @Override
        public void verify(JarVerificationContext context, List<X509Certificate> chain) throws Exception {
            if (chain.get(0).getSubjectDN().toString().equalsIgnoreCase("C=KR,O=Test,CN=Test Signer")) {
                context.setVerified(true);
            } else {
                context.setVerified(false);
            }
        }

        @Override
        public void end(JarVerificationContext context) {
        }
    }

    private void classLoadAndRun(JarPluginClassLoader classLoader) throws Exception {
        Class<?> clazz = classLoader.loadClass("hello.TestComponent");
        Object instance = clazz.newInstance();
        Method hello = clazz.getMethod("hello");
        String output = (String) hello.invoke(instance);
        assert output.equals("world");
    }

    @Test
    public void shouldPassIfAllowNonSigned() throws Exception {
        URL url = this.getClass().getResource("/test-component-1.0.1-nonsigned.jar");
        File file = new File(url.getPath());
        JarVerifier verifier = new JarVerifier(new DefaultVerificationHandler(true));
        JarPluginClassLoader classLoader =
                JarPluginClassLoader.newInstance(
                        Collections.singletonList(file),
                        this.getClass().getClassLoader(),
                        verifier
                );
        classLoadAndRun(classLoader);
    }

    @Test
    public void shouldFailIfDenyNonSigned() throws Exception {
        URL url = this.getClass().getResource("/test-component-1.0.1-nonsigned.jar");
        File file = new File(url.getPath());
        JarVerifier verifier = new JarVerifier(new DefaultVerificationHandler(false));
        assertThrows(SecurityException.class, () -> {
            try {
                JarPluginClassLoader classLoader =
                        JarPluginClassLoader.newInstance(
                                Collections.singletonList(file),
                                this.getClass().getClassLoader(),
                                verifier
                        );
                classLoadAndRun(classLoader);
            } catch (SecurityException e) {
                e.printStackTrace();
                throw e;
            }
        });
    }

    @Test()
    public void shouldPassIfVerifySucc() throws Exception {
        URL url = this.getClass().getResource("/test-component-1.0.1-signed.jar");
        File file = new File(url.getPath());
        JarVerifier verifier = new JarVerifier(new DefaultVerificationHandler(false));
        try {
            JarPluginClassLoader classLoader =
                    JarPluginClassLoader.newInstance(
                            Collections.singletonList(file),
                            this.getClass().getClassLoader(),
                            verifier
                    );
            classLoadAndRun(classLoader);
        } catch (SecurityException e) {
            e.printStackTrace();
            throw e;
        }
    }

    @Test()
    public void shouldFailIfVerifyFails() throws Exception {
        URL url = this.getClass().getResource("/test-component-1.0.1-wrong-signed.jar");
        File file = new File(url.getPath());
        JarVerifier verifier = new JarVerifier(new DefaultVerificationHandler(false));
        assertThrows(SecurityException.class, () -> {
            try {
                JarPluginClassLoader classLoader =
                        JarPluginClassLoader.newInstance(
                                Collections.singletonList(file),
                                this.getClass().getClassLoader(),
                                verifier
                        );
                classLoadAndRun(classLoader);
            } catch (SecurityException e) {
                e.printStackTrace();
                throw e;
            }
        });
    }
}
