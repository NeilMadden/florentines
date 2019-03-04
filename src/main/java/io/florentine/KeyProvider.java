package io.florentine;

import java.util.Optional;

public interface KeyProvider {
    Optional<FlorentineKey> getKeyById(String id);
    Optional<FlorentineKey> getKeyForIssuer(String issuer);
}
