package kr.jclab.javautils.pluginloader;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JarVerifier {
    private static Pattern SIG_FILE_PATTERN = Pattern.compile("^META-INF\\/([^/]+)\\.(SF|RSA|EC)$", Pattern.CASE_INSENSITIVE);
    private final JarVerificationHandler jarVerificationHandler;

    public JarVerifier(JarVerificationHandler jarVerificationHandler) {
        this.jarVerificationHandler = jarVerificationHandler;
    }

    private static class SignatureFile {
        JarEntry plainFile;
        JarEntry signatureFile;

        public SignatureFile(JarEntry plainFile, JarEntry signatureFile) {
            this.plainFile = plainFile;
            this.signatureFile = signatureFile;
        }
    }

    private boolean verifyCmsSignedData(JarVerificationContext context, CMSSignedData signedData) throws Exception {
        Store<X509CertificateHolder> certs = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BCProviderHolder.PROVIDER);

        for (Iterator<SignerInformation> iterator = signers.getSigners().iterator(); iterator.hasNext(); ) {
            SignerInformation signer = iterator.next();
            Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
            ArrayList<X509Certificate> chain = new ArrayList<>();
            for (X509CertificateHolder certHolder : certCollection) {
                chain.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded())));
            }
            if (chain.isEmpty()) {
                return false;
            }
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BCProviderHolder.PROVIDER)
                    .build(chain.get(0));
            if (!signer.verify(verifier)) {
                return false;
            }
            this.jarVerificationHandler.verify(context, chain);
        }

        return true;
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

        final JarVerificationContext context = this.jarVerificationHandler.createContext();
        this.jarVerificationHandler.start(context);

        for (Map.Entry<String, SignatureFile> entry : signatureFiles.entrySet()) {
            if (entry.getValue().signatureFile == null || entry.getValue().plainFile == null) {
                throw new SecurityException("Wrong signature: " + entry.getKey());
            }
            byte[] plainData = readFullyJarEntry(entry.getValue().plainFile, jarFile);
            byte[] signatureData = readFullyJarEntry(entry.getValue().signatureFile, jarFile);
            try {
                CMSSignedData block = new CMSSignedData(new CMSProcessableByteArray(plainData), signatureData);
                if (!verifyCmsSignedData(context, block)) {
                    throw new SecurityException("Failed to verify signature");
                }
            } catch (Exception e) {
                throw new SecurityException(e);
            }
        }

        this.jarVerificationHandler.end(context);

        if (!context.isVerified()) {
            throw new SecurityException("Failed to verify signature");
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
