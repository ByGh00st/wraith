//! Verify a signed release manifest before any executable is installed.
use crate::error::{Result, WraithError};
use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub version: String,
    pub target: String,
    pub sha256: String,
}

pub fn verify_signature(key: &str, content: &[u8], signature: &str) -> Result<()> {
    let key = PublicKey::decode(key)
        .map_err(|e| WraithError::Configuration(format!("Invalid trusted update key: {e}")))?;
    let signature = Signature::decode(signature)
        .map_err(|e| WraithError::Configuration(format!("Invalid update signature: {e}")))?;
    key.verify(content, &signature, false).map_err(|e| {
        WraithError::Configuration(format!("Update signature verification failed: {e}"))
    })
}

pub fn verify_release(
    key: &str,
    manifest: &[u8],
    signature: &str,
    binary: &[u8],
    current_version: &str,
) -> Result<ReleaseManifest> {
    verify_signature(key, manifest, signature)?;
    let manifest: ReleaseManifest = serde_json::from_slice(manifest)?;
    check_manifest(&manifest, binary, current_version)?;
    Ok(manifest)
}

fn check_manifest(manifest: &ReleaseManifest, binary: &[u8], current_version: &str) -> Result<()> {
    let version = semver::Version::parse(&manifest.version)
        .map_err(|e| WraithError::Configuration(e.to_string()))?;
    let current = semver::Version::parse(current_version)
        .map_err(|e| WraithError::Configuration(e.to_string()))?;
    if version <= current || !version.pre.is_empty() || !version.build.is_empty() {
        return Err(WraithError::Configuration(
            "Update must be a newer stable release; downgrade/replay refused".into(),
        ));
    }
    if manifest.target != "x86_64-unknown-linux-gnu" || !binary.starts_with(b"\x7fELF") {
        return Err(WraithError::Configuration(
            "Release target or executable format mismatch".into(),
        ));
    }
    if crate::crypto::Sha256::digest(binary).to_hex() != manifest.sha256 {
        return Err(WraithError::Configuration(
            "Release artifact hash mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public test vector from minisign-verify 0.2.5 (MIT), never a release trust key.
    const KEY: &str =
        "untrusted comment: test key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const SIG: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==";
    #[test]
    fn signature_rejects_modified_content_and_missing_key() {
        verify_signature(KEY, b"test", SIG).unwrap();
        assert!(verify_signature(KEY, b"Test", SIG).is_err());
        assert!(verify_signature("", b"test", SIG).is_err());
    }
    #[test]
    fn rejects_downgrades_and_artifact_substitution() {
        let binary = b"\x7fELFfixture";
        let mut manifest = ReleaseManifest {
            version: "1.4.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            sha256: crate::crypto::Sha256::digest(binary).to_hex(),
        };
        check_manifest(&manifest, binary, "1.3.0").unwrap();
        assert!(check_manifest(&manifest, b"\x7fELFchanged", "1.3.0").is_err());
        assert!(check_manifest(&manifest, binary, "1.4.0").is_err());
        manifest.target = "other-target".into();
        assert!(check_manifest(&manifest, binary, "1.3.0").is_err());
    }
}
