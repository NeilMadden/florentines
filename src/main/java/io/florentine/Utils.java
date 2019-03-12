package io.florentine;

import java.util.Iterator;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

final class Utils {

    static <T> Iterable<T> concat(Iterable<T> a, Iterable<T> b, Iterable<T> c) {
        Iterator<T> it1 = a.iterator();
        Iterator<T> it2 = b.iterator();
        Iterator<T> it3 = c.iterator();

        return () -> new Iterator<>() {
            @Override
            public boolean hasNext() {
                return it1.hasNext() || it2.hasNext() || it3.hasNext();
            }

            @Override
            public T next() {
                return it1.hasNext() ? it1.next() : it2.hasNext() ? it2.next() : it3.next();
            }
        };
    }

    static void destroyKeyMaterial(Destroyable... keys) {
        for (Destroyable key : keys) {
            if (key != null) {
                try {
                    key.destroy();
                } catch (DestroyFailedException e) {
                    // Ignore
                }
            }
        }
    }

    static byte[] reverse(byte[] x) {
        var y = new byte[x.length];
        var len = x.length;
        for (int i = 0; i < (len >>> 1); ++i) {
            y[i] = x[len - i + 1];
            y[len - i + 1] = x[i];
        }
        return y;
    }
}
