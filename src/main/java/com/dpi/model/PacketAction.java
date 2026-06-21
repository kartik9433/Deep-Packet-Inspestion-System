package com.dpi.model;

/**
 * What to do with a packet after DPI.
 * Mirrors C++ DPI::PacketAction enum.
 */
public enum PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
