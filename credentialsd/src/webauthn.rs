//! WebAuthn types re-exported from libwebauthn, plus origin/navigation types
//! used to validate and route incoming requests.

use std::{fmt::Display, str::FromStr};

pub use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDLResponse,
};

/// An application ID conforming to the
/// [XDG desktop entry syntax][xdg-desktop-entry-name].
///
/// [xdg-desktop-entry-name]: https://specifications.freedesktop.org/desktop-entry/latest/file-naming.html
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AppId(String);

impl AsRef<str> for AppId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for AppId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // begins with a letter
        match s.chars().nth(0) {
            Some(c) if c.is_ascii_alphabetic() => {}
            _ => return Err(()),
        };

        // alphanumeric and labels separated by dots
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(());
        }

        // All labels must be non-empty.
        if s.contains("..") {
            return Err(());
        }

        // ends with a valid label
        if s.ends_with('.') {
            return Err(());
        }
        Ok(AppId(s.to_string()))
    }
}

/// The origin of the client for the request.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Origin {
    Https {
        host: String,
        port: Option<u16>,
    },
    /// An `http` origin whose host is `localhost`.
    ///
    /// [WebAuthn §4 (RP ID)][rp-id] allows the `http` scheme only when the
    /// origin's host is `localhost`. Like libwebauthn, only the literal host
    /// `localhost` is accepted, not other loopback names or addresses.
    ///
    /// [rp-id]: https://www.w3.org/TR/webauthn-3/#rp-id
    HttpLocalhost {
        port: Option<u16>,
    },
    AppId(AppId),
}

impl Origin {
    /// Returns true if WebAuthn ceremonies may run in this origin: an `https`
    /// origin, or an `http` origin whose host is `localhost`.
    pub(crate) fn is_web_origin_allowed_for_webauthn(&self) -> bool {
        matches!(self, Origin::Https { .. } | Origin::HttpLocalhost { .. })
    }
}

impl Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Https { host, port } => {
                write!(f, "https://{}", host)?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                }
            }
            Origin::HttpLocalhost { port } => {
                write!(f, "http://localhost")?;
                if let Some(port) = port {
                    write!(f, ":{port}")?;
                }
            }
            Origin::AppId(app_id) => write!(f, "app:{}", app_id.0)?,
        }
        Ok(())
    }
}

impl TryFrom<&Origin> for RelyingPartyId {
    type Error = OriginParseError;

    /// Derives the relying party ID (effective domain) from an origin.
    ///
    /// AppId origins have no effective domain and must be mapped to an rpId
    /// out-of-band, so this conversion fails for them.
    fn try_from(origin: &Origin) -> Result<Self, Self::Error> {
        match origin {
            Origin::Https { host, .. } => {
                RelyingPartyId::try_from(host.as_str()).map_err(|_| OriginParseError::Host)
            }
            Origin::HttpLocalhost { .. } => {
                RelyingPartyId::try_from("localhost").map_err(|_| OriginParseError::Host)
            }
            Origin::AppId(_) => Err(OriginParseError::Scheme),
        }
    }
}

impl FromStr for Origin {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("https://") {
            let (host_candidate, port_candidate): (&str, Option<&str>) = rest
                .split_once(':')
                .map(|(h, p)| (h, Some(p)))
                .unwrap_or((rest, None));

            // begins with a letter
            match host_candidate.chars().nth(0) {
                Some(c) if c.is_ascii_alphabetic() => {}
                _ => return Err(OriginParseError::Host),
            };
            // alphanumeric with hyphens and labels separated by dots
            if !host_candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                return Err(OriginParseError::Host);
            }
            // ends with a valid label
            if host_candidate.ends_with('.') {
                return Err(OriginParseError::Host);
            }
            let host = host_candidate.to_ascii_lowercase();

            let Ok(port) = port_candidate.map(|p| p.parse()).transpose() else {
                return Err(OriginParseError::Port);
            };

            Ok(Origin::Https { host, port })
        } else if let Some(rest) = s.strip_prefix("http://") {
            let (host_candidate, port_candidate): (&str, Option<&str>) = rest
                .split_once(':')
                .map(|(h, p)| (h, Some(p)))
                .unwrap_or((rest, None));

            // The http scheme is only allowed for localhost.
            if !host_candidate.eq_ignore_ascii_case("localhost") {
                return Err(OriginParseError::Scheme);
            }

            let Ok(port) = port_candidate.map(|p| p.parse()).transpose() else {
                return Err(OriginParseError::Port);
            };

            Ok(Origin::HttpLocalhost { port })
        } else if let Some(app_id_candidate) = s.strip_prefix("app:") {
            let app_id = app_id_candidate
                .parse()
                .map_err(|_| OriginParseError::Host)?;
            Ok(Origin::AppId(app_id))
        } else {
            Err(OriginParseError::Scheme)
        }
    }
}

/// The origin of the request, and its top-level origin, if it is cross-origin.
#[derive(Debug)]
pub(crate) enum NavigationContext {
    /// Represents a client context with a single origin is presented to the user.
    SameOrigin(Origin),

    /// Represents a client context where the origin of the request is nested within
    /// another parent context with a different origin.
    CrossOrigin((Origin, Origin)),
}

#[derive(Debug)]
pub(crate) enum OriginParseError {
    Scheme,
    Host,
    Port,
}

impl std::error::Error for OriginParseError {}

impl Display for OriginParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scheme => f.write_str("Invalid scheme"),
            Self::Host => f.write_str("Invalid host"),
            Self::Port => f.write_str("Invalid port"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::webauthn::{Origin, OriginParseError, RelyingPartyId};

    fn check_https_origin(origin: &str, expected_host: &str, expected_port: Option<u16>) {
        let Origin::Https { host, port }: Origin = origin.parse().unwrap() else {
            panic!("Not an https origin");
        };
        assert_eq!(expected_host, host);
        assert_eq!(expected_port, port);
    }

    #[test]
    fn test_origin_parse_when_http_fails() {
        let err = "http://example.com".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::Scheme));
    }

    fn check_http_localhost_origin(origin: &str, expected_port: Option<u16>) {
        let Origin::HttpLocalhost { port }: Origin = origin.parse().unwrap() else {
            panic!("Not an http://localhost origin");
        };
        assert_eq!(expected_port, port);
    }

    #[test]
    fn test_origin_parse_http_localhost_succeeds() {
        check_http_localhost_origin("http://localhost", None);
    }

    #[test]
    fn test_origin_parse_http_localhost_with_port_succeeds() {
        check_http_localhost_origin("http://localhost:3000", Some(3000));
    }

    #[test]
    fn test_origin_parse_http_localhost_is_case_insensitive() {
        check_http_localhost_origin("http://LocalHost:3000", Some(3000));
    }

    #[test]
    fn test_origin_parse_http_localhost_round_trips() {
        for origin in ["http://localhost", "http://localhost:8080"] {
            assert_eq!(origin.parse::<Origin>().unwrap().to_string(), origin);
        }
        assert_eq!(
            "http://LOCALHOST".parse::<Origin>().unwrap().to_string(),
            "http://localhost"
        );
    }

    #[test]
    fn test_origin_parse_http_localhost_with_invalid_port_fails() {
        for origin in [
            "http://localhost:",
            "http://localhost:99999",
            "http://localhost:80/",
        ] {
            let err = origin.parse::<Origin>().unwrap_err();
            assert!(matches!(err, OriginParseError::Port), "{origin}");
        }
    }

    #[test]
    fn test_origin_parse_http_non_localhost_fails() {
        for origin in [
            "http://localhost.example.com",
            "http://sub.localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://localhost/",
            "http://evil.com#localhost",
            "http://",
        ] {
            let err = origin.parse::<Origin>().unwrap_err();
            assert!(matches!(err, OriginParseError::Scheme), "{origin}");
        }
    }

    #[test]
    fn test_http_localhost_relying_party_id_is_localhost() {
        let origin: Origin = "http://localhost:3000".parse().unwrap();
        let rp_id = RelyingPartyId::try_from(&origin).unwrap();
        assert_eq!(rp_id.to_string(), "localhost");
    }

    #[test]
    fn test_web_origins_are_allowed_for_webauthn() {
        for origin in ["https://example.com", "http://localhost:3000"] {
            let origin: Origin = origin.parse().unwrap();
            assert!(origin.is_web_origin_allowed_for_webauthn());
        }
        let app: Origin = "app:com.example.App".parse().unwrap();
        assert!(!app.is_web_origin_allowed_for_webauthn());
    }

    #[test]
    fn test_origin_parse_https_origin_without_port_succeeds() {
        check_https_origin("https://example.com", "example.com", None);
    }

    #[test]
    fn test_origin_parse_https_with_port_succeeds() {
        check_https_origin("https://example.org:8443", "example.org", Some(8443));
    }

    #[test]
    fn test_origin_parse_with_trailing_slash_fails() {
        let err = "https://example.org/".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::Host));
    }

    #[test]
    fn test_origin_parse_with_port_and_path_fails() {
        let err = "https://example.org:8443/".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::Port));
    }

    #[test]
    fn test_origin_parse_with_invalid_characters_fails() {
        let err = "https://😭.edu:1234".parse::<Origin>().unwrap_err();
        assert!(matches!(err, OriginParseError::Host));
    }

    #[test]
    fn test_origin_parse_app_id_succeeds() {
        let Origin::AppId(app_id) = "app:com.example.ExampleApp".parse::<Origin>().unwrap() else {
            panic!("not an app origin");
        };
        assert_eq!("com.example.ExampleApp", app_id.0);
    }
}
