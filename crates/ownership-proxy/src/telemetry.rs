use metrics_exporter_statsd::{StatsdBuilder, StatsdRecorder};
use telemetry_batteries::{MetricsBackend, StatsdConfig, TelemetryConfig, TelemetryGuard};

pub(crate) fn init() -> anyhow::Result<TelemetryGuard> {
    let mut config = TelemetryConfig::from_env()
        .map_err(|error| anyhow::anyhow!("loading telemetry configuration: {error:?}"))?;
    let recorder = recorder(&config.metrics.statsd, |name| std::env::var(name).ok())?;
    config.metrics.backend = MetricsBackend::None;
    let guard = telemetry_batteries::init_with_config(config)
        .map_err(|error| anyhow::anyhow!("initializing tracing: {error:?}"))?;
    metrics::set_global_recorder(recorder)?;
    Ok(guard)
}

fn recorder(
    config: &StatsdConfig,
    env: impl Fn(&str) -> Option<String>,
) -> Result<StatsdRecorder, metrics_exporter_statsd::StatsdError> {
    let mut builder = StatsdBuilder::from(&config.host, config.port)
        .with_queue_size(config.queue_size)
        .with_buffer_size(config.buffer_size);
    for (variable, tag) in [
        ("DD_SERVICE", "service"),
        ("DD_ENV", "env"),
        ("DD_VERSION", "version"),
        ("DD_ENTITY_ID", "dd.internal.entity_id"),
    ] {
        if let Some(value) = env(variable) {
            builder = builder.with_default_tag(tag, value);
        }
    }
    builder.build(config.prefix.as_deref())
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use super::*;

    #[test]
    fn metrics_carry_configured_default_tags() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let config = StatsdConfig {
            host: "127.0.0.1".into(),
            port: socket.local_addr().unwrap().port(),
            buffer_size: 1,
            prefix: Some("test".into()),
            ..StatsdConfig::default()
        };
        let recorder = recorder(&config, |name| match name {
            "DD_SERVICE" => Some("consumer".into()),
            "DD_ENV" => Some("stage".into()),
            "DD_VERSION" => Some("v1".into()),
            "DD_ENTITY_ID" => Some("pod-uid".into()),
            _ => None,
        })
        .unwrap();
        metrics::with_local_recorder(&recorder, || {
            metrics::histogram!("duration", "histogram" => "distribution").record(1.0);
        });
        let mut buffer = [0; 2048];
        let length = socket.recv(&mut buffer).unwrap();
        let packet = std::str::from_utf8(&buffer[..length]).unwrap();
        assert!(packet.starts_with("test.duration:1|d|#"), "{packet}");
        for tag in [
            "service:consumer",
            "env:stage",
            "version:v1",
            "dd.internal.entity_id:pod-uid",
        ] {
            assert!(packet.split([',', '#']).any(|part| part == tag), "{packet}");
        }
    }
    #[test]
    fn unset_variables_add_no_default_tags() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let config = StatsdConfig {
            host: "127.0.0.1".into(),
            port: socket.local_addr().unwrap().port(),
            buffer_size: 1,
            ..StatsdConfig::default()
        };
        let recorder = recorder(&config, |_| None).unwrap();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("requests").increment(1);
        });
        let mut buffer = [0; 2048];
        let length = socket.recv(&mut buffer).unwrap();
        assert_eq!(
            std::str::from_utf8(&buffer[..length]).unwrap(),
            "requests:1|c"
        );
    }
}
