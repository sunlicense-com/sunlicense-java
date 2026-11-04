package com.sunlicense;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Official SunLicense client for Java.
 *
 * <p>Early release. Licence validation works against the SunLicense REST API; the wider
 * client surface (activations, entitlements, offline verification) is in development.
 *
 * <p>Example:
 * <pre>{@code
 * SunLicense client = new SunLicense.Builder()
 *         .baseUrl("https://your-instance.example.com")
 *         .token(System.getenv("SUNLICENSE_TOKEN"))
 *         .build();
 *
 * SunLicense.Result result = client.validate("LICENCE-KEY-HERE");
 * if (result.isValid()) {
 *     getLogger().info("Licence valid");
 * }
 * }</pre>
 *
 * <p>This client has no third-party dependencies, so it is safe to shade into a plugin
 * without relocation conflicts.
 *
 * @see <a href="https://docs.sunlicense.hapangama.com">SunLicense documentation</a>
 */
public final class SunLicense {

    /** The version of this client. */
    public static final String VERSION = "0.2.0";

    private final String baseUrl;
    private final String token;
    private final HttpClient httpClient;
    private final Duration timeout;
    private final SunLicenseProtection protection;

    private SunLicense(Builder builder) {
        this.baseUrl = builder.baseUrl;
        this.token = builder.token;
        this.timeout = builder.timeout;
        this.protection = builder.protection == null ? null
                : builder.protection.baseUrl(builder.baseUrl).apiKey(builder.token).build();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(builder.timeout)
                .build();
    }

    /**
     * Validates a licence key.
     *
     * @param licenseKey the licence key to check; must not be {@code null} or empty
     * @return the outcome of the validation
     * @throws IllegalArgumentException if {@code licenseKey} is null or empty
     * @throws SunLicenseException      if the request fails or is interrupted
     */
    public Result validate(String licenseKey) {
        return validate(licenseKey, Map.of());
    }

    /**
     * Validates a licence key with additional context.
     *
     * @param licenseKey the licence key to check; must not be {@code null} or empty
     * @param context    extra fields to send, for example {@code product} or {@code host}
     * @return the outcome of the validation
     * @throws IllegalArgumentException if {@code licenseKey} is null or empty
     * @throws SunLicenseException      if the request fails or is interrupted
     */
    public Result validate(String licenseKey, Map<String, String> context) {
        if (licenseKey == null || licenseKey.isEmpty()) {
            throw new IllegalArgumentException("licenseKey must not be null or empty");
        }
        Objects.requireNonNull(context, "context");

        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("license", licenseKey);
        payload.putAll(context);
        if (protection != null) {
            // The same fields the server reads the machine from (fingerprint, hwid, host, macAddress).
            String machine = null;
            for (String k : new String[] {"fingerprint", "hwid", "host", "macAddress"}) {
                if (machine == null && context.get(k) != null && !context.get(k).isBlank()) {
                    machine = context.get(k);
                }
            }
            protection.license(licenseKey, machine);
            payload.putAll(protection.validateFields());
        }

        HttpRequest.Builder request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v2/license/validate"))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("User-Agent", "sunlicense-java/" + VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(toJson(payload)));

        if (token != null && !token.isEmpty()) {
            request.header("Authorization", "Bearer " + token);
        }

        try {
            HttpResponse<String> response =
                    httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
            boolean ok = response.statusCode() >= 200 && response.statusCode() < 300;
            if (protection != null && (response.statusCode() == 200 || response.statusCode() == 400)) {
                // A definite answer: keep (and cache) or forget the unlock. An outage changes nothing.
                protection.accept(response.body());
            }
            return new Result(ok, response.statusCode(), response.body());
        } catch (java.io.IOException e) {
            throw new SunLicenseException("SunLicense request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SunLicenseException("SunLicense request was interrupted", e);
        }
    }

    /**
     * Core unlock, tamper reports, the ownership notice and protected files for this client, when the builder
     * set {@link Builder#protection(SunLicenseProtection.Builder)}; {@code null} otherwise. Every
     * {@link #validate} feeds it: a valid answer's unlock is kept (and cached for 7 days on this machine), a
     * rejection forgets it, and an integrity result is sent with the next check.
     *
     * @return the protection bound to this client, or {@code null}
     */
    public SunLicenseProtection protection() {
        return protection;
    }

    /**
     * Built-in analytics for this licensed install, with this client's URL and API key: add the product
     * version and your config's switch, then {@code start()} it (see {@link SunLicenseAnalytics}).
     *
     * @param licenseKey the licence key this install validates
     * @param machineId  the machine id it validates with (the {@code host} you pass to {@link #validate})
     * @return a builder for the reporter
     */
    public SunLicenseAnalytics.Builder analytics(String licenseKey, String machineId) {
        return SunLicenseAnalytics.builder().baseUrl(baseUrl).apiKey(token).licenseKey(licenseKey).fingerprint(machineId);
    }

    /**
     * Starts built-in analytics for a free product, with its public product analytics id (Product → Analytics
     * in the dashboard). The first report goes 1 to 30 minutes later, then one every 30 minutes.
     *
     * @param productAnalyticsId the product's analytics id ({@code pa_…})
     * @return the running reporter; {@code close()} it on shutdown
     */
    public static SunLicenseAnalytics analytics(String productAnalyticsId) {
        return SunLicenseAnalytics.forProduct(productAnalyticsId);
    }

    /** Serialises a flat string map to JSON without pulling in a JSON library. */
    private static String toJson(Map<String, String> map) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('"').append(escape(entry.getKey())).append("\":\"")
                .append(escape(entry.getValue())).append('"');
        }
        return json.append('}').toString();
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder();
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"':  out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n");  break;
                case '\r': out.append("\\r");  break;
                case '\t': out.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    /** The outcome of a licence validation call. */
    public static final class Result {
        private final boolean valid;
        private final int status;
        private final String body;

        Result(boolean valid, int status, String body) {
            this.valid = valid;
            this.status = status;
            this.body = body;
        }

        /**
         * Returns whether the licence was accepted.
         *
         * @return {@code true} when the server accepted the licence
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * Returns the HTTP status code of the response.
         *
         * @return the HTTP status code
         */
        public int getStatus() {
            return status;
        }

        /**
         * Returns the raw response body.
         *
         * @return the response body, which callers may parse as JSON if needed
         */
        public String getBody() {
            return body;
        }

        @Override
        public String toString() {
            return "Result{valid=" + valid + ", status=" + status + '}';
        }
    }

    /** Thrown when a SunLicense request cannot be completed. */
    public static final class SunLicenseException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        SunLicenseException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Builds {@link SunLicense} instances. */
    public static final class Builder {
        private SunLicenseProtection.Builder protection;

        /** Creates a builder with default settings. */
        public Builder() {
        }

        private String baseUrl;
        private String token;
        private Duration timeout = Duration.ofSeconds(10);

        /**
         * Sets the base URL of your SunLicense instance.
         *
         * @param baseUrl base URL of your SunLicense instance; required
         * @return this builder
         */
        public Builder baseUrl(String baseUrl) {
            Objects.requireNonNull(baseUrl, "baseUrl");
            this.baseUrl = baseUrl.replaceAll("/+$", "");
            return this;
        }

        /**
         * Sets the API token used to authenticate requests.
         *
         * @param token API token, if your endpoint requires one
         * @return this builder
         */
        public Builder token(String token) {
            this.token = token;
            return this;
        }

        /**
         * Sets the request timeout.
         *
         * @param timeout request timeout; defaults to 10 seconds
         * @return this builder
         */
        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        /**
         * Builds the configured client.
         *
         * @return a new client
         * @throws IllegalStateException if {@code baseUrl} was never set
         */
        /**
         * Turns on core unlock, tamper reports, the ownership notice and protected files
         * (https://docs.sunlicense.com/guide/protection). This client's URL and API key are filled in.
         *
         * @param protection a {@link SunLicenseProtection#builder()} with at least the product code for protected files
         * @return this builder
         */
        public Builder protection(SunLicenseProtection.Builder protection) {
            this.protection = protection;
            return this;
        }

        public SunLicense build() {
            if (baseUrl == null || baseUrl.isEmpty()) {
                throw new IllegalStateException("baseUrl is required");
            }
            return new SunLicense(this);
        }
    }
}
