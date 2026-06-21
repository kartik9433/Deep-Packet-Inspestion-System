package com.dpi.model;

/**
 * Connection lifecycle states.
 * Mirrors C++ DPI::ConnectionState enum.
 */
public enum ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
}
