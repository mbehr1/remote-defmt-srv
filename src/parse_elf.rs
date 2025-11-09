use defmt_decoder::Table;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn};

pub async fn parse_elf_dir(elf_dir: &PathBuf) -> Vec<(String, PathBuf, Vec<u8>)> {
    let mut tables = Vec::new();
    // iterate over all .elf files in elf_dir and parse them
    if let Ok(mut entries) = tokio::fs::read_dir(elf_dir).await {
        // tokio::pin!(entries); ???
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            let path = entry.path().canonicalize().unwrap();
            if path.is_dir() {
                //warn!("Skipping directory {:?}", path);
                continue;
            }
            // info!("Parsing ELF file: {:?}", path);
            // TODO parse ELF file and store relevant data
            let bytes = fs::read(&path).await;
            if let Ok(bytes) = bytes {
                // Extract build ID
                let build_id = if let Some(build_id) = extract_build_id(&bytes) {
                    let build_id = hex::encode(&build_id);
                    info!("Build ID: {}", build_id);
                    build_id
                } else {
                    info!("No build ID found in {:?}. Skipping.", path);
                    continue;
                };
                let table = Table::parse(&bytes);
                match table {
                    Ok(Some(table)) => {
                        info!(
                            "Parsed defmt table from {:?}: {} entries",
                            path,
                            table.indices().count()
                        );
                        // store table somewhere
                        // as the Table is not clone, we keep the bytes and later recreate the Table
                        tables.push((build_id, path, bytes));
                    }
                    Ok(None) => {
                        info!("No defmt table found in {:?}", path);
                    }
                    Err(e) => {
                        warn!("Failed to parse defmt table from {:?}: {}", path, e);
                    }
                }
            } else {
                warn!(
                    "Failed to read ELF file {:?}: {}",
                    path,
                    bytes.err().unwrap()
                );
            }
        }
    }
    tables
}

fn extract_build_id(bytes: &[u8]) -> Option<Vec<u8>> {
    use object::{Object, ObjectSection};

    let file = object::File::parse(bytes).ok()?;

    // Look for .note.gnu.build-id section
    for section in file.sections() {
        if section.name().ok()? == ".note.gnu.build-id" {
            let data = section.data().ok()?;

            // Parse the note section
            // Note format: namesz (4 bytes), descsz (4 bytes), type (4 bytes), name, desc
            if data.len() < 12 {
                return None;
            }

            let namesz = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
            let descsz = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]) as usize;

            // Calculate aligned offset
            let name_offset = 12;
            let desc_offset = name_offset + ((namesz + 3) & !3); // Align to 4 bytes

            if data.len() >= desc_offset + descsz {
                return Some(data[desc_offset..desc_offset + descsz].to_vec());
            }
        }
    }

    None
}
