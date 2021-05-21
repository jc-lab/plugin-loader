package kr.jclab.javautils.pluginloader;

import java.io.Closeable;
import java.io.IOException;

public abstract class ProxyClassLoader implements Comparable<ProxyClassLoader>, Closeable {
    protected int order = 5;
    protected boolean lock = false;

    public final void lock() {
        this.lock = true;
    }

    public final boolean isLocked() {
        return lock;
    }

    public int getOrder() {
        return order;
    }

    public void setOrder(int order) {
        if (this.lock) throw new IllegalStateException("locked");
        this.order = order;
    }

    public abstract Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException;

    @Override
    public int compareTo(ProxyClassLoader o) {
        return this.order - o.getOrder();
    }

    @Override
    public void close() throws IOException {
    }
}
