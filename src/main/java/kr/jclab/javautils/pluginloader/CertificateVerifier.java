package kr.jclab.javautils.pluginloader;

import java.security.cert.X509Certificate;
import java.util.List;

@FunctionalInterface
public interface CertificateVerifier {
    void verify(List<X509Certificate> certificate) throws Exception;
}
