# HTTP Input Plugin

This plugin collects metrics from one or more HTTP endpoints providing data in
one of the supported [data formats][data_formats].

⭐ Telegraf v1.6.0
🏷️ applications, server
💻 all

[data_formats]: /docs/DATA_FORMATS_INPUT.md

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

In addition to the plugin-specific configuration settings, plugins support
additional global and plugin configuration settings. These settings are used to
modify metrics, tags, and field or create aliases and configure ordering, etc.
See the [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Secret-store support

This plugin supports secrets from secret-stores for the `username`, `password`,
`token`, `headers`, and `cookie_auth_headers` option.
See the [secret-store documentation][SECRETSTORE] for more details on how
to use them.

[SECRETSTORE]: ../../../docs/CONFIGURATION.md#secret-store-secrets

## Configuration

```toml @sample.conf
# Read formatted metrics from one or more HTTP endpoints
[[inputs.http]]
  ## One or more URLs from which to read formatted metrics.
  urls = [
    "http://localhost/metrics",
    "http+unix:///run/user/420/podman/podman.sock:/d/v4.0.0/libpod/pods/json"
  ]

  ## HTTP method
  # method = "GET"

  ## Optional HTTP headers
  # headers = {"X-Special-Header" = "Special-Value"}

  ## HTTP entity-body to send with POST/PUT requests.
  # body = ""

  ## HTTP Content-Encoding for write request body, can be set to "gzip" to
  ## compress body or "identity" to apply no encoding.
  # content_encoding = "identity"

  ## Optional Bearer token settings to use for the API calls.
  ## Use either the token itself or the token file if you need a token.
  # token = "eyJhbGc...Qssw5c"
  # token_file = "/path/to/file"
  # remove_bearer_token_prefix = false

  ## Optional HTTP Basic Auth Credentials
  # username = "username"
  # password = "pa$$word"

  ## OAuth2 Client Credentials. The options 'client_id', 'client_secret', and 'token_url' are required to use OAuth2.
  # client_id = "clientid"
  # client_secret = "secret"
  # token_url = "https://indentityprovider/oauth2/v1/token"
  # scopes = ["urn:opc:idm:__myscopes__"]

  ## HTTP Proxy support
  # use_system_proxy = false
  # http_proxy_url = ""

  ## Optional TLS Config
  ## Set to true/false to enforce TLS being enabled/disabled. If not set,
  ## enable TLS only if any of the other options are specified.
  # tls_enable =
  ## Trusted root certificates for server
  # tls_ca = "/path/to/cafile"
  ## Used for TLS client certificate authentication
  # tls_cert = "/path/to/certfile"
  ## Used for TLS client certificate authentication
  # tls_key = "/path/to/keyfile"
  ## Password for the key file if it is encrypted
  # tls_key_pwd = ""
  ## Send the specified TLS server name via SNI
  # tls_server_name = "kubernetes.example.com"
  ## Minimal TLS version to accept by the client
  # tls_min_version = "TLS12"
  ## List of ciphers to accept, by default all secure ciphers will be accepted
  ## See https://pkg.go.dev/crypto/tls#pkg-constants for supported values.
  ## Use "all", "secure" and "insecure" to add all support ciphers, secure
  ## suites or insecure suites respectively.
  # tls_cipher_suites = ["secure"]
  ## Renegotiation method, "never", "once" or "freely"
  # tls_renegotiation_method = "never"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false

  ## Optional Cookie authentication
  # cookie_auth_url = "https://localhost/authMe"
  # cookie_auth_method = "POST"
  # cookie_auth_username = "username"
  # cookie_auth_password = "pa$$word"
  # cookie_auth_headers = { Content-Type = "application/json", X-MY-HEADER = "hello" }
  # cookie_auth_body = '{"username": "user", "password": "pa$$word", "authenticate": "me"}'
  ## cookie_auth_renewal not set or set to "0" will auth once and never renew the cookie
  # cookie_auth_renewal = "5m"

  ## Amount of time allowed to complete the HTTP request
  # timeout = "5s"

  ## List of success status codes
  # success_status_codes = [200]

  ## Data format to consume.
  ## Each data format has its own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_INPUT.md
  # data_format = "influx"

```

HTTP requests over Unix domain sockets can be specified via the "http+unix" or
"https+unix" schemes.
Request URLs should have the following form:

```text
http+unix:///path/to/service.sock:/api/endpoint
```

Note: The path to the Unix domain socket and the request endpoint are separated
by a colon (":").

## Example Output

This example output was taken from [this instructional article][1].

[1]: https://docs.influxdata.com/telegraf/v1/configure_plugins/input_plugins/using_http/

```text
citibike,station_id=4703 eightd_has_available_keys=false,is_installed=1,is_renting=1,is_returning=1,legacy_id="4703",num_bikes_available=6,num_bikes_disabled=2,num_docks_available=26,num_docks_disabled=0,num_ebikes_available=0,station_status="active" 1641505084000000000
citibike,station_id=4704 eightd_has_available_keys=false,is_installed=1,is_renting=1,is_returning=1,legacy_id="4704",num_bikes_available=10,num_bikes_disabled=2,num_docks_available=36,num_docks_disabled=0,num_ebikes_available=0,station_status="active" 1641505084000000000
citibike,station_id=4711 eightd_has_available_keys=false,is_installed=1,is_renting=1,is_returning=1,legacy_id="4711",num_bikes_available=9,num_bikes_disabled=0,num_docks_available=36,num_docks_disabled=0,num_ebikes_available=1,station_status="active" 1641505084000000000
```

## Metrics

The metrics collected by this input plugin will depend on the configured
`data_format` and the payload returned by the HTTP endpoint(s).

The default values below are added if the input format does not specify a value:

- http
  - tags:
    - url

## Optional Cookie Authentication Settings

The optional Cookie Authentication Settings will retrieve a cookie from the
given authorization endpoint, and use it in subsequent API requests.  This is
useful for services that do not provide OAuth or Basic Auth authentication,
e.g. the [Tesla Powerwall API][tesla], which uses a Cookie Auth Body to retrieve
an authorization cookie.  The Cookie Auth Renewal interval will renew the
authorization by retrieving a new cookie at the given interval.

[tesla]: https://www.tesla.com/support/energy/powerwall/own/monitoring-from-home-network
