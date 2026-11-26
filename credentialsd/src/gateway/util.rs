//! This module contains types and methods used for serializing data to and from D-Bus method calls.
//!
//! Types shared between components within this service belong in credentialsd_common::model.

use libwebauthn::ops::webauthn::idl::origin::{
    Origin as LibwebauthnOrigin, RequestOrigin as LibwebauthnRequestOrigin,
};
use libwebauthn::ops::webauthn::psl::SystemPublicSuffixList;
use libwebauthn::ops::webauthn::{
    MaxRegistrableLabels, OriginValidation, RelatedOrigins, RequestSettings,
    ReqwestRelatedOriginsSource,
};

use crate::{
    gateway::{
        CreateCredentialRequest, CreatePublicKeyCredentialResponse, GetCredentialRequest,
        GetPublicKeyCredentialResponse, WebAuthnError,
    },
    model::{GetAssertionResponseInternal, MakeCredentialResponseInternal},
    webauthn::{
        GetAssertionRequest, MakeCredentialRequest, NavigationContext, Origin, WebAuthnIDLResponse,
    },
};

impl TryFrom<&Origin> for LibwebauthnOrigin {
    type Error = WebAuthnError;

    fn try_from(value: &Origin) -> Result<Self, Self::Error> {
        match value {
            Origin::Https { .. } | Origin::HttpLocalhost { .. } => {
                value.to_string().parse().map_err(|err| {
                    tracing::info!("Cannot convert origin to libwebauthn Origin: {err}");
                    WebAuthnError::SecurityError
                })
            }
            // TODO: AppId support is being removed.
            Origin::AppId(_) => unimplemented!("AppId origins are not supported"),
        }
    }
}

impl TryFrom<&NavigationContext> for LibwebauthnRequestOrigin {
    type Error = WebAuthnError;

    fn try_from(value: &NavigationContext) -> Result<Self, Self::Error> {
        match value {
            NavigationContext::SameOrigin(o) => Ok(LibwebauthnRequestOrigin::new(o.try_into()?)),
            NavigationContext::CrossOrigin((o, top)) => Ok(
                LibwebauthnRequestOrigin::new_cross_origin(o.try_into()?, top.try_into()?),
            ),
        }
    }
}

fn load_system_psl() -> Result<SystemPublicSuffixList, WebAuthnError> {
    SystemPublicSuffixList::auto().map_err(|err| {
        tracing::error!("Failed to load system Public Suffix List: {err}");
        WebAuthnError::NotAllowedError
    })
}

fn build_related_origins_source() -> Result<ReqwestRelatedOriginsSource, WebAuthnError> {
    ReqwestRelatedOriginsSource::new().map_err(|err| {
        tracing::error!("Failed to build related-origins source: {err}");
        WebAuthnError::NotAllowedError
    })
}

fn request_settings<'a>(
    psl: &'a SystemPublicSuffixList,
    related_origins: &'a ReqwestRelatedOriginsSource,
) -> RequestSettings<'a> {
    RequestSettings {
        origin: OriginValidation::Validate {
            public_suffix_list: psl,
            related_origins: RelatedOrigins::Enabled {
                source: related_origins,
                max_labels: MaxRegistrableLabels::default(),
            },
        },
    }
}

/// Parses a WebAuthn create credential request from D-Bus into a CTAP2 MakeCredentialRequest.
pub(super) async fn create_credential_request_try_into_ctap2(
    request: &CreateCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<MakeCredentialRequest, WebAuthnError> {
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: missing public_key");
        WebAuthnError::NotSupportedError
    })?;

    let request_origin: LibwebauthnRequestOrigin = request_environment.try_into()?;
    let psl = load_system_psl()?;
    let related_origins = build_related_origins_source()?;
    let settings = request_settings(&psl, &related_origins);

    let make_cred_request =
        MakeCredentialRequest::prepare(&request_origin, &options.request_json, &settings)
            .await
            .map_err(|err| {
                tracing::info!("Failed to parse MakeCredential request JSON: {err}");
                WebAuthnError::TypeError
            })?;

    Ok(make_cred_request)
}

/// Serializes a CTAP2 MakeCredentialResponse to WebAuthn JSON format.
///
/// Uses libwebauthn's `WebAuthnIDLResponse::to_idl_model()` for serialization, then adds
/// transport and authenticator-attachment information that is known at the credential
/// service level.
pub(super) fn create_credential_response_try_from_ctap2(
    response: &MakeCredentialResponseInternal,
    request: &MakeCredentialRequest,
) -> std::result::Result<CreatePublicKeyCredentialResponse, String> {
    let mut registration_json = response
        .ctap
        .to_idl_model(request)
        .map_err(|err| format!("Failed to serialize registration response: {err}"))?;

    // TODO(libwebauthn#159): transports and authenticatorAttachment should be
    // populated by libwebauthn once it has access to transport-level information.
    registration_json.response.transports = response.transport.clone();
    registration_json.authenticator_attachment = Some(response.attachment_modality.clone());

    let registration_response_json = serde_json::to_string(&registration_json)
        .map_err(|err| format!("Failed to serialize registration response to JSON: {err}"))?;

    Ok(CreatePublicKeyCredentialResponse {
        registration_response_json,
    })
}

/// Parses a WebAuthn get credential request from D-Bus into a CTAP2 GetAssertionRequest.
pub(super) async fn get_credential_request_try_into_ctap2(
    request: &GetCredentialRequest,
    request_environment: &NavigationContext,
) -> std::result::Result<GetAssertionRequest, WebAuthnError> {
    let options = request.public_key.as_ref().ok_or_else(|| {
        tracing::info!("Invalid request: no \"publicKey\" options specified.");
        WebAuthnError::NotSupportedError
    })?;

    let request_origin: LibwebauthnRequestOrigin = request_environment.try_into()?;
    let psl = load_system_psl()?;
    let related_origins = build_related_origins_source()?;
    let settings = request_settings(&psl, &related_origins);

    let get_assertion_request =
        GetAssertionRequest::prepare(&request_origin, &options.request_json, &settings)
            .await
            .map_err(|err| {
                tracing::info!("Failed to parse GetAssertion request JSON: {err}");
                WebAuthnError::TypeError
            })?;

    Ok(get_assertion_request)
}

/// Serializes a CTAP2 GetAssertionResponse to WebAuthn JSON format.
///
/// Uses libwebauthn's `WebAuthnIDLResponse::to_idl_model()` for serialization, then adds
/// authenticator-attachment information that is known at the credential service level.
pub(super) fn get_credential_response_try_from_ctap2(
    response: &GetAssertionResponseInternal,
    request: &GetAssertionRequest,
) -> std::result::Result<GetPublicKeyCredentialResponse, String> {
    let mut authentication_json = response
        .ctap
        .to_idl_model(request)
        .map_err(|err| format!("Failed to serialize authentication response: {err}"))?;

    // TODO(libwebauthn#159): authenticatorAttachment should be populated by
    // libwebauthn once it has access to transport-level information.
    authentication_json.authenticator_attachment = Some(response.attachment_modality.clone());

    let authentication_response_json = serde_json::to_string(&authentication_json)
        .map_err(|err| format!("Failed to serialize authentication response to JSON: {err}"))?;

    Ok(GetPublicKeyCredentialResponse {
        authentication_response_json,
    })
}

#[cfg(test)]
mod test {
    use libwebauthn::ops::webauthn::idl::origin::RequestOrigin as LibwebauthnRequestOrigin;
    use libwebauthn::ops::webauthn::{
        OriginValidation, PublicSuffixList, RelatedOrigins, RequestSettings, SYSTEM_PSL_DAFSA_PATH,
        SYSTEM_PSL_PATH,
    };

    use super::get_credential_request_try_into_ctap2;
    use crate::gateway::{GetCredentialRequest, GetPublicKeyCredentialRequest, WebAuthnError};
    use crate::webauthn::{GetAssertionRequest, NavigationContext, Origin};

    /// "a challenge", base64url-encoded without padding.
    const CHALLENGE: &str = "YSBjaGFsbGVuZ2U";

    /// Treats the last label of a host as its public suffix, which is enough
    /// for the hosts used in these tests.
    struct LastLabelPublicSuffixList;

    impl PublicSuffixList for LastLabelPublicSuffixList {
        fn public_suffix(&self, host: &str) -> Option<String> {
            host.rsplit('.').next().map(str::to_string)
        }
    }

    fn origin(s: &str) -> Origin {
        s.parse().unwrap()
    }

    fn request_json(rp_id: &str) -> String {
        format!(r#"{{"challenge": "{CHALLENGE}", "rpId": "{rp_id}"}}"#)
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Prepares a GetAssertion request the way the gateway does, validating
    /// the RP ID against the origin, but with a fixed public suffix list.
    fn prepare_get_assertion(
        context: &NavigationContext,
        rp_id: &str,
    ) -> Result<GetAssertionRequest, WebAuthnError> {
        let request_origin: LibwebauthnRequestOrigin = context.try_into()?;
        let settings = RequestSettings {
            origin: OriginValidation::Validate {
                public_suffix_list: &LastLabelPublicSuffixList,
                related_origins: RelatedOrigins::Disabled,
            },
        };
        block_on(GetAssertionRequest::prepare(
            &request_origin,
            &request_json(rp_id),
            &settings,
        ))
        .map_err(|_| WebAuthnError::SecurityError)
    }

    #[test]
    fn test_same_origin_client_data_omits_top_origin() {
        let context = NavigationContext::SameOrigin(origin("https://example.com"));
        let request = prepare_get_assertion(&context, "example.com").unwrap();
        assert_eq!(
            request.client_data_json(),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{CHALLENGE}","origin":"https://example.com","crossOrigin":false}}"#
            )
        );
    }

    #[test]
    fn test_cross_origin_client_data_with_equal_top_origin() {
        // Issue #276: A -> B -> A must keep `crossOrigin: true`.
        let context = NavigationContext::CrossOrigin((
            origin("https://example.com"),
            origin("https://example.com"),
        ));
        let request = prepare_get_assertion(&context, "example.com").unwrap();
        assert_eq!(
            request.client_data_json(),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{CHALLENGE}","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://example.com"}}"#
            )
        );
    }

    #[test]
    fn test_cross_origin_client_data_with_different_top_origin() {
        let context = NavigationContext::CrossOrigin((
            origin("https://idp.example.net"),
            origin("https://example.com"),
        ));
        let request = prepare_get_assertion(&context, "example.net").unwrap();
        assert_eq!(
            request.client_data_json(),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{CHALLENGE}","origin":"https://idp.example.net","crossOrigin":true,"topOrigin":"https://example.com"}}"#
            )
        );
    }

    #[test]
    fn test_http_localhost_client_data() {
        // Issue #277: http://localhost is a valid WebAuthn origin.
        let context = NavigationContext::SameOrigin(origin("http://localhost:3000"));
        let request = prepare_get_assertion(&context, "localhost").unwrap();
        assert_eq!(request.relying_party_id, "localhost");
        assert_eq!(
            request.client_data_json(),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{CHALLENGE}","origin":"http://localhost:3000","crossOrigin":false}}"#
            )
        );
    }

    #[test]
    fn test_http_localhost_cannot_claim_other_rp_id() {
        let context = NavigationContext::SameOrigin(origin("http://localhost:3000"));
        assert!(prepare_get_assertion(&context, "example.com").is_err());
    }

    #[test]
    fn test_https_origin_cannot_claim_localhost_rp_id() {
        let context = NavigationContext::SameOrigin(origin("https://example.com"));
        assert!(prepare_get_assertion(&context, "localhost").is_err());
    }

    /// Runs the gateway's conversion with the system public suffix list, as
    /// the daemon does. Skipped when no system list is installed.
    #[test]
    fn test_http_localhost_with_system_public_suffix_list() {
        if !std::path::Path::new(SYSTEM_PSL_DAFSA_PATH).exists()
            && !std::path::Path::new(SYSTEM_PSL_PATH).exists()
        {
            eprintln!("Skipping: no system public suffix list installed");
            return;
        }
        let request = GetCredentialRequest {
            public_key: Some(GetPublicKeyCredentialRequest {
                request_json: request_json("localhost"),
            }),
        };
        let context = NavigationContext::SameOrigin(origin("http://localhost"));
        let request = block_on(get_credential_request_try_into_ctap2(&request, &context)).unwrap();
        assert_eq!(request.relying_party_id, "localhost");
        assert_eq!(request.origin, "http://localhost");
        assert_eq!(request.top_origin, None);
    }
}
