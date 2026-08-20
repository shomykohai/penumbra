use penumbra_mtk::storage::gpt::GPT_SIZE;
use penumbra_mtk::storage::{EmmcStorage, GptType, UfsStorage};
use penumbra_mtk::traits::FromBytes;
use penumbra_mtk::{Gpt, Partition, Storage, StorageKind};

const GPT: &[u8] = include_bytes!("../files/storage/PGPT.bin");
const EMMC_RESP: &[u8] = include_bytes!("../files/storage/emmc_resp.bin");
const UFS_XML_RESP: &str = include_str!("../files/storage/ufs_resp.xml");

const PART_COUNT: usize = 76;

const HDR: usize = 0x1000;
const HDR_LAST_USABLE_LBA: usize = HDR + 48;
const HDR_NUM_ENTRIES: usize = HDR + 80;
const HDR_ENTRY_SIZE: usize = HDR + 84;
const ENTRY_ARRAY: usize = 0x2000;

fn ufs_storage() -> StorageKind {
    StorageKind::Ufs(UfsStorage::from_xml(UFS_XML_RESP).expect("UFS storage should parse"))
}

fn emmc_storage() -> StorageKind {
    StorageKind::Emmc(EmmcStorage::from_bytes(EMMC_RESP).expect("eMMC storage should parse"))
}

// TODO: Perhaps use a crate that adds support for fixtures
fn fixture() -> Gpt {
    Gpt::from_bytes(GPT).expect("Fixture GPT should parse")
}

#[test]
fn test_gpt_parse() {
    let gpt = fixture();

    assert!(gpt.is_valid(), "GPT should be valid");

    let storage = emmc_storage();
    let parts = gpt.to_partitions(&storage);

    assert_eq!(parts.len(), PART_COUNT, "There should be {PART_COUNT} partitions");

    let new_gpt = Gpt::from_partitions(&parts, &storage, GptType::Sgpt)
        .expect("SGPT should be created successfully");

    assert!(new_gpt.is_valid(), "New GPT should be valid");

    let new_pgpt = Gpt::from_partitions(&parts, &storage, GptType::Pgpt)
        .expect("PGPT should be created successfully");

    assert!(new_pgpt.is_valid(), "New PGPT should be valid");

    let new_gpt_bytes = new_pgpt.to_bytes().expect("New GPT should serialize successfully");
    let new_pgpt_read = Gpt::from_bytes(&new_gpt_bytes).expect("New GPT should parse successfully");

    assert!(new_pgpt_read.is_valid(), "New GPT read should be valid");
}

#[test]
fn test_gpt_partition_addresses() {
    let parts = fixture().to_partitions(&ufs_storage());

    assert_eq!(parts.len(), PART_COUNT);

    let expected: [(&str, u64, u64); 6] = [
        ("misc", 0x8000, 0x80000),
        ("para", 0x88000, 0x80000),
        ("expdb", 0x108000, 0x8000000),
        ("super", 0x5C800000, 0x182000000),
        ("userdata", 0x1DE800000, 0x39B67F8000),
        ("flashinfo", 0x3B94FF8000, 0x1000000),
    ];

    for (name, address, size) in expected {
        let part = parts
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("Partition {name} should be present"));

        assert_eq!(part.address, address, "{name} address");
        assert_eq!(part.size, size, "{name} size");
    }

    assert!(parts.iter().all(|p| p.address >= 0x8000), "No partition can overlap the GPT");
    assert!(parts.iter().all(|p| p.address % 0x1000 == 0), "Addresses must be block aligned");
}

#[test]
fn test_gpt_first_and_last_partition() {
    let parts = fixture().to_partitions(&ufs_storage());

    assert_eq!(parts.first().expect("Should yield back a partition").name, "misc");
    assert_eq!(parts.last().expect("Should yield back a partition").name, "flashinfo");
}

fn gen_gpt(gpt_type: GptType, storage: StorageKind) {
    let parts = fixture().to_partitions(&storage);

    assert_eq!(parts.len(), PART_COUNT);

    let generated =
        Gpt::from_partitions(&parts, &storage, gpt_type).expect("GPT should be generated");

    assert!(generated.is_valid(), "Generated GPT should be valid");

    let bytes = generated.to_bytes().expect("Generated GPT should serialize successfully");
    let reparsed = Gpt::from_bytes(&bytes).expect("Generated GPT should parse back just fine");

    assert!(reparsed.is_valid(), "Re-parsed GPT should be valid");

    let reparsed_parts = reparsed.to_partitions(&storage);

    assert_eq!(
        reparsed_parts.len(),
        parts.len(),
        "Partiiton count shouldn't change between generations"
    );

    for (original, reparsed) in parts.iter().zip(reparsed_parts.iter()) {
        assert_eq!(original.name, reparsed.name, "Name must be the same between generations");
        assert_eq!(original.address, reparsed.address, "{} address should match", original.name);
        assert_eq!(original.size, reparsed.size, "{} size should match", original.name);
    }
}

#[test]
fn test_pgpt_gen_ufs() {
    gen_gpt(GptType::Pgpt, ufs_storage());
}

#[test]
fn test_sgpt_gen_ufs() {
    gen_gpt(GptType::Sgpt, ufs_storage());
}

#[test]
fn test_pgpt_gen_emmc() {
    gen_gpt(GptType::Pgpt, emmc_storage());
}

#[test]
fn test_sgpt_gen_emmc() {
    gen_gpt(GptType::Sgpt, emmc_storage());
}

#[test]
fn test_sgpt_buffer_gen() {
    let storage = ufs_storage();
    let parts = fixture().to_partitions(&storage);

    let sgpt = Gpt::from_partitions(&parts, &storage, GptType::Sgpt).expect("SGPT");
    let bytes = sgpt.to_bytes().expect("SGPT should serialize");

    let wire_len = (GPT_SIZE / 2) + storage.block_size() as usize;
    let tail = &bytes[bytes.len() - wire_len..];

    let reparsed = Gpt::from_bytes(tail).expect("SGPT should parse successfully");

    assert!(reparsed.is_valid());
    assert_eq!(reparsed.to_partitions(&storage).len(), PART_COUNT);
}

#[test]
fn test_gpt_invalid() {
    let mut invalid_data = GPT.to_vec();

    invalid_data[HDR] = 0xFF;

    let gpt = Gpt::from_bytes(&invalid_data);

    assert!(gpt.is_err(), "GPT parsing should fail for invalid data");
}

#[test]
fn test_gpt_truncated() {
    let truncated_data = &GPT[..HDR];

    let gpt = Gpt::from_bytes(truncated_data);

    assert!(gpt.is_err(), "GPT parsing should fail for truncated data");
}

#[test]
fn test_gpt_entry_corruption_rejection() {
    for offset in [ENTRY_ARRAY, ENTRY_ARRAY + 0x40, ENTRY_ARRAY + (PART_COUNT - 1) * 128] {
        let mut data = GPT.to_vec();
        data[offset] ^= 0xFF;

        assert!(
            Gpt::from_bytes(&data).is_err(),
            "Corrupted entry array at {offset:#x} should be rejected"
        );
    }
}

#[test]
fn test_gpt_header_corruption() {
    let mut data = GPT.to_vec();
    data[HDR_LAST_USABLE_LBA] ^= 0xFF;

    assert!(Gpt::from_bytes(&data).is_err(), "Corrupted header should not parse");
}

#[test]
fn test_gpt_malformed_entry() {
    let mut zero_entry_size = GPT.to_vec();
    zero_entry_size[HDR_ENTRY_SIZE..HDR_ENTRY_SIZE + 4].copy_from_slice(&0u32.to_le_bytes());

    assert!(Gpt::from_bytes(&zero_entry_size).is_err(), "Zero entry size should be rejected");

    let mut out_of_range_count = GPT.to_vec();
    out_of_range_count[HDR_NUM_ENTRIES..HDR_NUM_ENTRIES + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(Gpt::from_bytes(&out_of_range_count).is_err(), "absurd entry count should be rejected");

    let mut out_of_range_size = GPT.to_vec();
    out_of_range_size[HDR_ENTRY_SIZE..HDR_ENTRY_SIZE + 4].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(Gpt::from_bytes(&out_of_range_size).is_err(), "absurd entry size should be rejected");
}

#[test]
fn test_gpt_gen_matches_part_count() {
    let storage = emmc_storage();
    let parts = fixture().to_partitions(&storage);

    let new_pgpt = Gpt::from_partitions(&parts, &storage, GptType::Pgpt)
        .expect("PGPT should be created successfully");
    let new_bytes = new_pgpt.to_bytes().expect("New GPT should serialize successfully");
    let reparsed = Gpt::from_bytes(&new_bytes).expect("New GPT bytes should parse successfully");
    let new_parts = reparsed.to_partitions(&storage);

    assert_eq!(
        new_parts.len(),
        parts.len(),
        "Generated GPT should have every partition ({} vs original {})",
        new_parts.len(),
        parts.len()
    );
}

#[test]
fn test_gpt_skips_zero_size() {
    let storage = ufs_storage();
    let parts = vec![
        Partition::new("misc", 0x80000, 0x8000, storage.get_user_part()),
        Partition::new("empty", 0, 0x100000, storage.get_user_part()),
    ];
    let gpt = Gpt::from_partitions(&parts, &storage, GptType::Pgpt)
        .expect("GPT should be created successfully");
    let out = gpt.to_partitions(&storage);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "misc");
}

#[test]
fn test_gpt_sub_block_rounds_up() {
    let storage = ufs_storage();
    let parts = vec![Partition::new("tiny", 100, 0x8000, storage.get_user_part())];
    let gpt = Gpt::from_partitions(&parts, &storage, GptType::Pgpt)
        .expect("GPT should be created successfully");
    let out = gpt.to_partitions(&storage);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].address, 0x8000);
    assert_eq!(out[0].size, 0x1000);
}
