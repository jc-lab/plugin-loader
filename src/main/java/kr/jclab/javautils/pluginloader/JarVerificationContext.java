package kr.jclab.javautils.pluginloader;

public final class JarVerificationContext {
    private boolean verified = false;

    public final boolean isVerified() {
        return verified;
    }

    public final void setVerified(boolean verified) {
        this.verified = verified;
    }
}
