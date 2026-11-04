package com.sunlicense;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** The shared SDK test vectors (validation's seal format, spec 203): every official SDK must pass them. */
class ProtectionVectorsTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static final Path VECTORS = Path.of("src/test/resources/protection-test-vectors.json");

    JsonNode vectors() throws Exception {
        assumeTrue(Files.isRegularFile(VECTORS), "built outside the repository");
        return JSON.readTree(Files.readString(VECTORS));
    }

    SunLicenseProtection unlockedWith(String productKeyBase64) {
        SunLicenseProtection p = SunLicenseProtection.builder().licenseKey("AX8P-K7QX-M2PD-9HWT").cacheDirectory(null).build();
        p.accept(true, productKeyBase64);
        return p;
    }

    @Test
    void sealedVectorsOpenToTheirDataAndDigests() throws Exception {
        JsonNode sealed = vectors().path("sealed");
        assertThat(sealed.size()).isPositive();
        for (JsonNode v : sealed) {
            SunLicenseProtection p = unlockedWith(v.path("productKeyBase64").asText());
            byte[] data = p.unseal(v.path("sealed").asText());
            assertThat(data).as(v.path("name").asText()).isEqualTo(Base64.getDecoder().decode(v.path("dataBase64").asText()));
            Map<String, String> digests = new LinkedHashMap<>();
            v.path("digests").fields().forEachRemaining(e -> digests.put(e.getKey(), e.getValue().asText()));
            assertThat(p.digests()).as(v.path("name").asText()).isEqualTo(digests);
            // Padded base64url opens too.
            String s = v.path("sealed").asText();
            String padded = s + "=".repeat((4 - (s.length() - 5) % 4) % 4);
            assertThat(unlockedWith(v.path("productKeyBase64").asText()).unseal(padded)).isEqualTo(data);
        }
    }

    @Test
    void mustFailVectorsStayLocked() throws Exception {
        for (JsonNode v : vectors().path("mustFail")) {
            SunLicenseProtection p = unlockedWith(v.path("productKeyBase64").asText());
            assertThatThrownBy(() -> p.unseal(v.path("sealed").asText())).as(v.path("name").asText())
                    .isInstanceOf(SunLicenseProtection.Locked.class);
        }
    }

    @Test
    void digestVectors() throws Exception {
        for (JsonNode v : vectors().path("digests")) {
            if (v.has("normalised")) {
                assertThat(SunLicenseProtection.normalDigest(v.path("input").asText())).isEqualTo(v.path("normalised").asText());
                continue;
            }
            byte[] input = v.has("inputUtf8") ? v.path("inputUtf8").asText().getBytes(StandardCharsets.UTF_8)
                    : Base64.getDecoder().decode(v.path("inputBase64").asText());
            assertThat(SunLicenseProtection.hex(SunLicenseProtection.sha256(input))).isEqualTo(v.path("sha256Hex").asText());
        }
    }

    @Test
    void integrityAgainstTheVectorsDigests() throws Exception {
        JsonNode first = vectors().path("sealed").get(0);
        SunLicenseProtection p = unlockedWith(first.path("productKeyBase64").asText());
        p.unseal(first.path("sealed").asText());
        JsonNode jar = null;
        for (JsonNode d : vectors().path("digests")) {
            if (d.has("inputBase64")) {
                jar = d;
            }
        }
        byte[] bytes = Base64.getDecoder().decode(jar.path("inputBase64").asText());
        assertThat(p.integrity(name -> name.equals("plugin.jar") ? bytes : null, p.digests())).isEqualTo("OK");
        assertThat(p.integrity(name -> new byte[] {1}, p.digests())).isEqualTo("MODIFIED");
    }

    @Test
    void wireAnswersCarryTheUnlock() throws Exception {
        JsonNode wire = vectors().path("wire");
        for (String answer : new String[] {"validateResponseV1", "compatResponseV2"}) {
            SunLicenseProtection p = SunLicenseProtection.builder().licenseKey("AX8P-K7QX-M2PD-9HWT").cacheDirectory(null).build();
            p.accept(JSON.writeValueAsString(wire.path(answer)));
            assertThat(p.unlocked()).as(answer).isTrue();
            JsonNode sealed = vectors().path("sealed").get(0);
            assertThat(p.unseal(sealed.path("sealed").asText())).isNotEmpty();
        }
    }
}
