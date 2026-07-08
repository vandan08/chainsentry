package io.chainsentry.scanner;

import io.chainsentry.shared.model.ScannerType;

public class ScannerExecutionException extends Exception {

    private final ScannerType engine;

    public ScannerExecutionException(ScannerType engine, String message, Throwable cause) {
        super("[" + engine + "] " + message, cause);
        this.engine = engine;
    }

    public ScannerType engine() {
        return engine;
    }
}
