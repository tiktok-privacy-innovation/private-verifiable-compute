use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use kbs_types::Tee;
use nvml_wrapper::{
    Nvml, enums::device::DeviceArchitecture, structs::device::ConfidentialComputeGpuCapabilities,
};
use serde::Serialize;
use serde_json::Value;
use types::ReportData;

/// NRAS knows about "switch" and "gpu" but the expected evidence
/// content is the same. nvidia-attester can compose a list of
/// all CC enabled nvml/nscq devices using this evidence struct.
#[derive(Serialize)]
struct NvDeviceReportAndCert {
    arch: DeviceArchitecture,
    uuid: String,
    evidence: String,
    certificate: String,
}

#[derive(Serialize)]
struct NvDeviceEvidence {
    device_evidence_list: Vec<NvDeviceReportAndCert>,
}

const NVIDIA_NONCE_SIZE: usize = 32;

pub fn detect_nvidia_device() -> bool {
    // Return true iff one GPU is found and it has CC mode set.
    match Nvml::init() {
        Ok(nvml) => {
            nvml.device_count().is_ok_and(|count| count == 1)
                && nvml.device_by_index(0).is_ok_and(|device| {
                    device
                        .get_confidential_compute_capabilities()
                        .is_ok_and(|c| c.gpus_caps == ConfidentialComputeGpuCapabilities::Capable)
                })
        }
        Err(e) => {
            error!("failed to initialize nvml: {:?}", e);
            false
        }
    }
}

pub async fn get_nvidia_evidence(report_data: ReportData) -> Result<Option<(Tee, Value)>> {
    if detect_nvidia_device() {
        let tee_type = Tee::Nvidia;
        let nvml = Nvml::init()?;
        let devices = nvml.device_count()?;

        let mut device_evidence_list = vec![];

        let nonce: [u8; NVIDIA_NONCE_SIZE] = report_data[0..NVIDIA_NONCE_SIZE].try_into()?;

        for index in 0..devices {
            let device = nvml.device_by_index(index)?;

            let report = device
                .confidential_compute_gpu_attestation_report(nonce)
                .context("Failed to get attestation report for device {index}")?;

            let certificate = device
                .confidential_compute_gpu_certificate()
                .context("Failed to get certificate for device {index}")?;

            let dev_arch = device
                .architecture()
                .context("Failed to get architecture for device {index}")?;

            let dev_uuid = device
                .uuid()
                .context("Failed to get UUID for device {index}")?;

            device_evidence_list.push(NvDeviceReportAndCert {
                arch: dev_arch,
                uuid: dev_uuid,
                evidence: STANDARD.encode(report.attestation_report),
                certificate: STANDARD.encode(certificate.attestation_cert_chain),
            });

            device
                .set_confidential_compute_state(true)
                .context("Failed to set device {index} to ready state")?;

            // Skip confidential compute status check
            // if !device
            //     .check_confidential_compute_status()
            //     .is_ok_and(|status| status)
            // {
            //     bail!("NVIDIA attester: device {index} CC status check failed")
            // }
        }

        let full_evidence = NvDeviceEvidence {
            device_evidence_list,
        };

        let evidence =
            serde_json::to_value(&full_evidence).context("Serialize NVIDIA evidence failed")?;
        info!("device devidence: {:?} ,{}", tee_type, evidence);
        return Ok(Some((tee_type, evidence)));
    }

    Ok(None)
}
