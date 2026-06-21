package com.dpi;

import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import com.dpi.model.ParsedPacket;
import com.dpi.service.PacketParserService;
import com.dpi.service.SniExtractorService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class DpiEngineTests {

    @Autowired PacketParserService parserService;
    @Autowired SniExtractorService sniExtractor;

    // -----------------------------------------------------------------------
    // PacketParser tests
    // -----------------------------------------------------------------------

    @Test
    void testIpToString() {
        // 0x08080808 = 8.8.8.8 in big-endian
        assertEquals("8.8.8.8", PacketParserService.ipToString(0x08080808));
        assertEquals("192.168.1.1", PacketParserService.ipToString(0xC0A80101));
    }

    @Test
    void testMacToString() {
        byte[] mac = {(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF};
        assertEquals("aa:bb:cc:dd:ee:ff", PacketParserService.macToString(mac));
    }

    @Test
    void testParseNullData() {
        ParsedPacket result = parserService.parse(null, 0, 0);
        assertNull(result);
    }

    @Test
    void testParseTooSmall() {
        ParsedPacket result = parserService.parse(new byte[5], 0, 0);
        assertNull(result);
    }

    // -----------------------------------------------------------------------
    // FiveTuple tests
    // -----------------------------------------------------------------------

    @Test
    void testFiveTupleEquals() {
        FiveTuple a = new FiveTuple("1.2.3.4", "5.6.7.8", 12345, 443, 6);
        FiveTuple b = new FiveTuple("1.2.3.4", "5.6.7.8", 12345, 443, 6);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void testFiveTupleReverse() {
        FiveTuple orig = new FiveTuple("1.2.3.4", "5.6.7.8", 1234, 443, 6);
        FiveTuple rev  = orig.reverse();
        assertEquals("5.6.7.8", rev.getSrcIp());
        assertEquals("1.2.3.4", rev.getDstIp());
        assertEquals(443,  rev.getSrcPort());
        assertEquals(1234, rev.getDstPort());
    }

    @Test
    void testFiveTupleToString() {
        FiveTuple t = new FiveTuple("192.168.1.1", "8.8.8.8", 54321, 443, 6);
        assertTrue(t.toString().contains("192.168.1.1"));
        assertTrue(t.toString().contains("TCP"));
    }

    // -----------------------------------------------------------------------
    // AppType SNI classification tests
    // -----------------------------------------------------------------------

    @Test
    void testSniClassification() {
        assertEquals(AppType.GOOGLE,    AppType.fromSni("www.google.com"));
        assertEquals(AppType.YOUTUBE,   AppType.fromSni("www.youtube.com"));
        assertEquals(AppType.FACEBOOK,  AppType.fromSni("www.facebook.com"));
        assertEquals(AppType.NETFLIX,   AppType.fromSni("www.netflix.com"));
        assertEquals(AppType.DISCORD,   AppType.fromSni("discord.gg"));
        assertEquals(AppType.GITHUB,    AppType.fromSni("api.github.com"));
        assertEquals(AppType.UNKNOWN,   AppType.fromSni("some-random-domain.io"));
        assertEquals(AppType.UNKNOWN,   AppType.fromSni(null));
    }

    // -----------------------------------------------------------------------
    // SniExtractor tests
    // -----------------------------------------------------------------------

    @Test
    void testSniExtractorNullPayload() {
        assertNull(sniExtractor.extract(null));
    }

    @Test
    void testSniExtractorEmptyPayload() {
        assertNull(sniExtractor.extract(new byte[0]));
    }

    @Test
    void testSniExtractorNonTlsPayload() {
        // HTTP GET request — not TLS
        byte[] httpData = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes();
        assertNull(sniExtractor.extract(httpData));
    }
}
