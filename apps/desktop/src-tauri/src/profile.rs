use std::path::PathBuf;

use directories::BaseDirs;
use lattice_platform::OsKeyringProtector;

const PROFILE_ID: &str = "default";
const DATABASE_NAME: &str = "lattice.sqlite";

pub(crate) fn data_dir() -> Result<PathBuf, String> {
    let data_dir = BaseDirs::new()
        .map(|directories| {
            directories
                .data_local_dir()
                .join("Astraive")
                .join("Lattice")
        })
        .ok_or_else(|| "user data directory is unavailable".to_owned())?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|error| format!("create app data directory: {error}"))?;
    Ok(data_dir)
}

pub(crate) fn open_profile() -> Result<(PathBuf, OsKeyringProtector), String> {
    let data_dir = data_dir()?;
    let protector = OsKeyringProtector::new(PROFILE_ID).map_err(|error| error.to_string())?;
    Ok((data_dir.join(DATABASE_NAME), protector))
}
