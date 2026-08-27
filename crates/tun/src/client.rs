use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use tokio::net::UnixStream;
use tracing::debug;

use crate::frame::{recv_frame, send_frame};
use crate::ipc::{socket_path_from_env, ApplySpec, HelperRequest, HelperResponse, IPC_VERSION};
use crate::{Result, TunError};

pub struct HelperClient {
    stream: UnixStream,
    path: PathBuf,
}

impl HelperClient {
    pub async fn connect_default() -> Result<Self> {
        Self::connect(socket_path_from_env()).await
    }

    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let stream = UnixStream::connect(&path).await.map_err(|e| {
            TunError::HelperUnavailable(format!(
                "{} ({e}). Full-tunnel mode will try pkexec, or start manually: sudo easy-helper --allow-uid $(id -u)",
                path.display()
            ))
        })?;
        Ok(Self { stream, path })
    }

    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    async fn roundtrip(
        &self,
        req: &HelperRequest,
        expect_fd: bool,
    ) -> Result<(HelperResponse, Option<OwnedFd>)> {
        let (send_op, recv_op) = match req {
            HelperRequest::Ping { .. } => ("helper send Ping", "helper recv Pong"),
            HelperRequest::Cleanup => ("helper send Cleanup", "helper recv Cleanup result"),
            HelperRequest::Apply { .. } => ("helper send Apply", "helper recv Apply result"),
            HelperRequest::Teardown => ("helper send Teardown", "helper recv Teardown result"),
            HelperRequest::EmergencyRestore => (
                "helper send EmergencyRestore",
                "helper recv EmergencyRestore result",
            ),
        };
        let payload = serde_json::to_vec(req)?;
        send_frame(&self.stream, &payload, None, send_op).await?;
        let frame = recv_frame(&self.stream, recv_op).await?;
        let resp: HelperResponse = serde_json::from_slice(&frame.payload)?;
        if let HelperResponse::Error { message } = &resp {
            return Err(TunError::HelperRejected(message.clone()));
        }
        if expect_fd && frame.fd.is_none() {
            return Err(TunError::Ipc(
                "helper Apply succeeded but no TUN file descriptor was passed".into(),
            ));
        }
        Ok((resp, frame.fd))
    }

    pub async fn ping(&self) -> Result<HelperResponse> {
        let (resp, _) = self
            .roundtrip(
                &HelperRequest::Ping {
                    version: IPC_VERSION,
                },
                false,
            )
            .await?;
        Ok(resp)
    }

    pub async fn cleanup(&self) -> Result<String> {
        let (resp, _) = self.roundtrip(&HelperRequest::Cleanup, false).await?;
        Ok(match resp {
            HelperResponse::Ok { message, .. } => message,
            other => format!("{other:?}"),
        })
    }

    pub async fn apply(&self, spec: ApplySpec) -> Result<(String, OwnedFd)> {
        spec.validate().map_err(TunError::Ipc)?;
        debug!(session = %spec.session_id, "requesting helper Apply");
        let (resp, fd) = self.roundtrip(&HelperRequest::Apply { spec }, true).await?;
        let fd = fd.expect("checked");
        let message = match resp {
            HelperResponse::Ok { message, .. } => message,
            other => format!("{other:?}"),
        };
        Ok((message, fd))
    }

    pub async fn teardown(&self) -> Result<String> {
        let (resp, _) = self.roundtrip(&HelperRequest::Teardown, false).await?;
        Ok(match resp {
            HelperResponse::Ok { message, .. } => message,
            other => format!("{other:?}"),
        })
    }

    pub async fn emergency_restore(&self) -> Result<String> {
        let (resp, _) = self
            .roundtrip(&HelperRequest::EmergencyRestore, false)
            .await?;
        Ok(match resp {
            HelperResponse::Ok { message, .. } => message,
            other => format!("{other:?}"),
        })
    }
}
