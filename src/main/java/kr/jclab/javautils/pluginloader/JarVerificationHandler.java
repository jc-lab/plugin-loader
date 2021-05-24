package kr.jclab.javautils.pluginloader;

import java.security.cert.X509Certificate;
import java.util.List;

public interface JarVerificationHandler {
    default JarVerificationContext createContext() {
        return new JarVerificationContext();
    }
    void start(JarVerificationContext context);
    void verify(JarVerificationContext context, List<X509Certificate> chain) throws Exception;
    void end(JarVerificationContext context);
}
