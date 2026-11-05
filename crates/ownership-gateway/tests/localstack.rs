//! KMS signing against `LocalStack`.

use std::{sync::Arc, time::Duration};

use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{
    config::Credentials,
    types::{KeySpec, KeyUsageType},
};
use ownership_gateway::{
    retry::Deadline,
    signing::{AwsKms, DEFAULT_FAILURE_THRESHOLD, KmsSigner, load_jwk},
};
use p256::ecdsa::{Signature, signature::Verifier as _};
use testcontainers::{ImageExt as _, core::IntoContainerPort as _, runners::AsyncRunner as _};
use testcontainers_modules::localstack::LocalStack;

/// The `LocalStack` image from ECR Public, which does not rate-limit CI as Docker Hub does.
const LOCALSTACK_IMAGE: &str = "public.ecr.aws/localstack/localstack";
const LOCALSTACK_TAG: &str = "3.0.2";

#[tokio::test]
async fn signs_with_a_localstack_p256_key() {
    let container = tokio::time::timeout(
        Duration::from_secs(120),
        LocalStack::default()
            .with_name(LOCALSTACK_IMAGE)
            .with_tag(LOCALSTACK_TAG)
            .with_env_var("SERVICES", "kms")
            .with_mapped_port(0, 4566.tcp())
            .start(),
    )
    .await
    .unwrap()
    .unwrap();
    let port = container.get_host_port_ipv4(4566).await.unwrap();
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new("test", "test", None, None, "localstack"))
        .endpoint_url(format!("http://127.0.0.1:{port}"))
        .load()
        .await;
    let client = aws_sdk_kms::Client::new(&config);
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        client
            .create_key()
            .key_spec(KeySpec::EccNistP256)
            .key_usage(KeyUsageType::SignVerify)
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    let key_id = output.key_metadata().unwrap().key_id().to_owned();
    let kms = Arc::new(AwsKms::new(&config));
    let key = load_jwk(kms.as_ref(), &key_id).await.unwrap();
    let signer = KmsSigner::load(kms, key_id, DEFAULT_FAILURE_THRESHOLD)
        .await
        .unwrap();
    let signature = signer
        .sign(b"header.payload", Deadline::after(Duration::from_secs(5)))
        .await
        .unwrap();
    key.public_key()
        .verify(
            b"header.payload",
            &Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    assert_eq!(signer.kid(), key.kid());
}
