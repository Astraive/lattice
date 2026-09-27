use std::path::{Path, PathBuf};

use directories::BaseDirs;
use lattice_platform::OsKeyringProtector;
const PROFILE_ID: &str = "default";
const DATABASE_NAME: &str = "lattice.sqlite";
/// Debug builds only: isolate Desktop app data and keyring entries for local
/// acceptance runs without touching the current user's normal profile.
const DEBUG_PROFILE_DIR_ENV: &str = "LATTICE_DESKTOP_PROFILE_DIR";

pub(crate) fn data_dir() -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(data_dir) = std::env::var_os(DEBUG_PROFILE_DIR_ENV) {
        let data_dir = PathBuf::from(data_dir);
        if !data_dir.is_absolute() {
            return Err(format!("{DEBUG_PROFILE_DIR_ENV} must be an absolute path"));
        }
        std::fs::create_dir_all(&data_dir)
            .map_err(|error| format!("create isolated profile directory: {error}"))?;
        return data_dir
            .canonicalize()
            .map_err(|error| format!("resolve isolated profile directory: {error}"));
    }

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

fn keyring_profile_id(data_dir: &Path, isolated: bool) -> String {
    #[cfg(not(debug_assertions))]
    let _ = data_dir;
    if isolated {
        #[cfg(debug_assertions)]
        {
            // Stable FNV-1a keeps the per-directory keyring slot across builds.
            let hash = data_dir
                .to_string_lossy()
                .bytes()
                .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
                });
            return format!("desktop-debug-{hash:016x}");
        }
        #[cfg(not(debug_assertions))]
        unreachable!("release builds cannot select an isolated profile");
    }

    PROFILE_ID.to_owned()
}

pub(crate) fn open_profile() -> Result<(PathBuf, OsKeyringProtector), String> {
    let isolated = cfg!(debug_assertions) && std::env::var_os(DEBUG_PROFILE_DIR_ENV).is_some();
    let data_dir = data_dir()?;
    let protector = OsKeyringProtector::new(&keyring_profile_id(&data_dir, isolated))
        .map_err(|error| error.to_string())?;
    Ok((data_dir.join(DATABASE_NAME), protector))
}

#[cfg(test)]
mod tests {
    use super::keyring_profile_id;
    use std::path::Path;

    #[test]
    fn isolated_profile_ids_are_stable_and_path_specific() {
        let first = Path::new(r"C:\lattice-test\one");
        let second = Path::new(r"C:\lattice-test\two");
        assert_eq!(
            keyring_profile_id(first, true),
            keyring_profile_id(first, true)
        );
        assert_ne!(
            keyring_profile_id(first, true),
            keyring_profile_id(second, true)
        );
        assert_eq!(keyring_profile_id(first, false), "default");
    }
}
