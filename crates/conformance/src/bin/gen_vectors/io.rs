// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn ensure_dir(dir: &Path) -> Result<(), VectorGenError> {
    fs::create_dir_all(dir).map_err(|_| VectorGenError::CreateVectorsDirectory)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), VectorGenError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| VectorGenError::SerializeJson)?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|_| VectorGenError::WriteJson)
}

fn vectors_dir() -> Result<PathBuf, VectorGenError> {
    let conformance_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = conformance_dir
        .parent()
        .and_then(Path::parent)
        .ok_or(VectorGenError::VectorsDirectory)?;
    Ok(repo_root.join("vectors"))
}
