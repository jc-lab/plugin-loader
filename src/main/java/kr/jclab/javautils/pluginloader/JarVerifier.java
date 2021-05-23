package kr.jclab.javautils.pluginloader;

import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;

import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JarVerifier {
    private static Pattern SIG_FILE_PATTERN = Pattern.compile("^META-INF\\/([^/]+)\\.(SF|RSA|EC)$", Pattern.CASE_INSENSITIVE);
    private final CertificateVerifier certificateChainVerifier;

    public JarVerifier(CertificateVerifier certificateChainVerifier) {
        this.certificateChainVerifier = certificateChainVerifier;
    }

    private static class SignatureFile {
        JarEntry plainFile;
        JarEntry signatureFile;

        public SignatureFile(JarEntry plainFile, JarEntry signatureFile) {
            this.plainFile = plainFile;
            this.signatureFile = signatureFile;
        }
    }

    public final void verify(JarFile jarFile) throws IOException, SecurityException {
        byte[] dummy = new byte[1024];
        final HashMap<String, SignatureFile> signatureFiles = new HashMap<>();

        // Verify the hash of the classes with the manifest.
        Enumeration<JarEntry> entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            final JarEntry entry = entries.nextElement();

            // TODO: Signed Class Just File
            final CodeSigner[] codeSigner = entry.getCodeSigners();

            final Matcher matcher = SIG_FILE_PATTERN.matcher(entry.getName());
            if (matcher.find()) {
                final String signerName = matcher.group(1).toLowerCase();
                final String extName = matcher.group(2).toLowerCase();
                if (extName.equals("sf")) {
                    signatureFiles.compute(signerName, (key, old) -> {
                        if (old != null) {
                            old.plainFile = entry;
                            return old;
                        } else {
                            return new SignatureFile(entry, null);
                        }
                    });
                } else {
                    signatureFiles.compute(signerName, (key, old) -> {
                        if (old != null) {
                            old.signatureFile = entry;
                            return old;
                        } else {
                            return new SignatureFile(null, entry);
                        }
                    });
                }
            }
            try (InputStream inputStream = jarFile.getInputStream(entry)) {
                // automatic throw SecurityException if a Signature/Digest check fails.
                while (inputStream.read(dummy) > 0);
            }
        }

        for (Map.Entry<String, SignatureFile> entry : signatureFiles.entrySet()) {
            if (entry.getValue().signatureFile == null || entry.getValue().plainFile == null) {
                throw new SecurityException("Wrong signature: " + entry.getKey());
            }
            byte[] plainData = readFullyJarEntry(entry.getValue().plainFile, jarFile);
            byte[] signatureData = readFullyJarEntry(entry.getValue().signatureFile, jarFile);
            try {
                PKCS7 block = new PKCS7(signatureData);
                SignerInfo[] verifiedSignerInfos = block.verify(plainData);
                if ((verifiedSignerInfos == null) || (verifiedSignerInfos.length == 0)) {
                    throw new SecurityException("Failed to verify signature: no verified SignerInfos");
                }
                SignerInfo verifiedSignerInfo = verifiedSignerInfos[0];
                final List<X509Certificate> verifiedSignerCertChain = verifiedSignerInfo.getCertificateChain(block);
                if (verifiedSignerCertChain == null) {
                    // Should never happen
                    throw new SecurityException("Failed to find verified SignerInfo certificate chain");
                } else if (verifiedSignerCertChain.isEmpty()) {
                    // Should never happen
                    throw new SecurityException("Verified SignerInfo certificate chain is emtpy");
                }
                this.certificateChainVerifier.verify(verifiedSignerCertChain);
            } catch (Exception e) {
                throw new SecurityException(e);
            }
        }
    }

    private static byte[] readFullyJarEntry(JarEntry entry, JarFile file) throws IOException {
        byte[] buffer = new byte[(int) entry.getSize()];
        try (InputStream inputStream = file.getInputStream(entry)) {
            int readBytes;
            int offset = 0;
            while ((readBytes = inputStream.read(buffer, offset, buffer.length - offset)) > 0) {
                offset += readBytes;
            }
            if (offset != buffer.length) {
                throw new IOException("error");
            }
            return buffer;
        }
    }
}
