package io.florentine;

public enum MacAlgorithm {
    HS512("HmacSHA512");

    private final String macAlgorithm;

    MacAlgorithm(String macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    String getMacAlgorithm() {
        return macAlgorithm;
    }

    String getKeyAlgorthm() { return macAlgorithm; }

    int getKeySizeBytes() {
        return 32;
    }

    @Override
    public String toString() {
        return name();
    }
}
