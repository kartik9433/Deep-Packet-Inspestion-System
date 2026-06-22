package com.dpi.model;

/**
 * Application types detected via Deep Packet Inspection.
 * Mirrors the C++ DPI::AppType enum.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Specific applications detected via SNI
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;


    public static AppType fromSni(String sni) {
        if (sni == null || sni.isBlank()) return UNKNOWN;
        String lower = sni.toLowerCase();

        if (lower.contains("google") || lower.contains("gstatic") || lower.contains("googleapis")) return GOOGLE;
        if (lower.contains("youtube") || lower.contains("ytimg")) return YOUTUBE;
        if (lower.contains("facebook") || lower.contains("fbcdn")) return FACEBOOK;
        if (lower.contains("instagram")) return INSTAGRAM;
        if (lower.contains("twitter") || lower.contains("twimg")) return TWITTER;
        if (lower.contains("netflix") || lower.contains("nflxvideo")) return NETFLIX;
        if (lower.contains("amazon") || lower.contains("amazonaws")) return AMAZON;
        if (lower.contains("microsoft") || lower.contains("windows") || lower.contains("azure")) return MICROSOFT;
        if (lower.contains("apple") || lower.contains("icloud")) return APPLE;
        if (lower.contains("whatsapp")) return WHATSAPP;
        if (lower.contains("telegram")) return TELEGRAM;
        if (lower.contains("tiktok") || lower.contains("bytedance")) return TIKTOK;
        if (lower.contains("spotify")) return SPOTIFY;
        if (lower.contains("zoom.us") || lower.contains("zoom.com")) return ZOOM;
        if (lower.contains("discord")) return DISCORD;
        if (lower.contains("github")) return GITHUB;
        if (lower.contains("cloudflare")) return CLOUDFLARE;

        return UNKNOWN;
    }
}
