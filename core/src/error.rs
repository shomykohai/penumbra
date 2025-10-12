/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// An error related to XFlash protocol (and its error codes)
    #[error("XFlash error: {0}")]
    XFlash(#[from] XFlashError),
    /// Generic Protocol error
    #[error("Protocol Error {0}")]
    Protocol(String),
    /// Connection specific error
    #[error("Connection Error: {0}")]
    Connection(String),
    /// Error related to I/O operations
    /// In particular with the connection backends
    #[error("I/O Error: {0}")]
    Io(String),
    /// Generic error that happens in Penumbra, can
    /// be used for anything
    #[error("Penumbra Error: {0}")]
    Penumbra(String),
    /// Error that takes a status code and formats it as hex.
    /// When dealing with statuses in general, use
    /// this, unless a more specific implementation
    /// is there (e.g. XFlash)
    #[error("{ctx}: Status is 0x{status:X}")]
    Status { ctx: String, status: u32 },
}

impl Error {
    pub fn io<S: Into<String>>(msg: S) -> Self {
        Error::Io(msg.into())
    }

    pub fn conn<S: Into<String>>(msg: S) -> Self {
        Error::Connection(msg.into())
    }

    pub fn proto<S: Into<String>>(msg: S) -> Self {
        Error::Protocol(msg.into())
    }

    pub fn penumbra<S: Into<String>>(msg: S) -> Self {
        Error::Penumbra(msg.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::penumbra(value.to_string())
    }
}

/*
    XFlash error codes work as follows:

    There are four severity levels:
    * Success (0 << 30, or 0x00000000)
    * Info    (1 << 30, or 0x40000000)
    * Warning (2 << 30, or 0x80000000)
    * Error   (3 << 30, or 0xC0000000)

    Then, follows the "domain" of this error code
    relates to:
    * Common     (1)
    * Security   (2)
    * Library    (3)
    * Device/HW  (4)
    * Host?      (5)
    * BROM       (6)
    * DA         (7)
    * Preloader  (8)

    Finally, the actual error code (0x01-...)

    Example:
    0xc0070004 => 0xC0000000 (Error) | 7 << 16 (domain) | 0x4 (code)
*/
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
pub enum XFlashErrorKind {
    #[error("Generic error")]
    Error = 0xc0010001,
    #[error("Abort")]
    Abort = 0xc0010002,
    #[error("Unsupported command")]
    UnsupportedCommand = 0xc0010003,
    #[error("Unsupported devctrl code")]
    UnsupportedCtrlCode = 0xc0010004,
    #[error("Protocol error")]
    ProtocolError = 0xc0010005,
    #[error("Protocol buffer overflow")]
    ProtocolBufferOverflow = 0xc0010006,
    #[error("Insufficient buffer")]
    InsufficientBuffer = 0xc0010007,
    #[error("USB SCAN error")]
    UsbScanError = 0xc0010008,
    #[error("Invalid hsession")]
    InvalidHSession = 0xc0010009,
    #[error("Invalid session")]
    InvalidSession = 0xc001000A,
    #[error("Invalid stage")]
    InvalidStage = 0xc001000B,
    #[error("Not implemented")]
    NotImplemented = 0xc001000C,
    #[error("File not found")]
    FileNotFound = 0xc001000D,
    #[error("Open file error")]
    OpenFileError = 0xc001000E,
    #[error("Write file error")]
    WriteFileError = 0xc001000F,
    #[error("Read file error")]
    ReadFileError = 0xc0010010,
    #[error("Create File error / Unsupported Version")]
    CreateFileErrorOrUnsupportedVersion = 0xc0010011, // In XML these two errors are separated

    // Security
    #[error("SEC: Rom info not found")]
    RomInfoNotFound = 0xc0020001,
    #[error("SEC: Cust name not found")]
    CustNameNotFound = 0xc0020002,
    #[error("SEC: Device not supported")]
    DeviceNotSupported = 0xc0020003,
    #[error("SEC: Download forbidden (region is not whitelisted)")]
    DlForbidden = 0xc0020004,
    #[error("SEC: Image too large")]
    ImgTooLarge = 0xc0020005,
    #[error("SEC: Preloader verify failed")]
    PlVerifyFailed = 0xc0020006,
    #[error("SEC: Image verify failed")]
    ImageVerifyFailed = 0xc0020007,
    #[error("SEC: Hash operation failed")]
    HashOperationFailed = 0xc0020008,
    #[error("SEC: Hash binding check failed")]
    HashBindingCheckFailed = 0xc0020009,
    #[error("SEC: Invalid buffer")]
    InvalidBuf = 0xc002000a,
    #[error("SEC: Binding hash not available")]
    BindingHashNotAvailable = 0xc002000b,
    #[error("SEC: Write data not allowed (region is not whitelisted)")]
    WriteDataNotAllowed = 0xc002000c,
    #[error("SEC: Format not allowed (region is not whitelisted)")]
    FormatNotAllowed = 0xc002000d,
    #[error("SEC: SV5 public key auth failed")]
    Sv5PubKeyAuthFailed = 0xc002000e,
    #[error("SEC: SV5 hash verify failed")]
    Sv5HashVerifyFailed = 0xc002000f,
    #[error("SEC: SV5 RSA operation failed")]
    Sv5RsaOpFailed = 0xc0020010,
    #[error("SEC: SV5 RSA verify failed")]
    Sv5RsaVerifyFailed = 0xc0020011,
    #[error("SEC: SV5 GFH not found")]
    Sv5GfhNotFound = 0xc0020012,
    #[error("SEC: Invalid cert1")]
    Cert1Invalid = 0xc0020013,
    #[error("SEC: Invalid cert2")]
    Cert2Invalid = 0xc0020014,
    #[error("SEC: Image header invalid")]
    ImghdrInvalid = 0xc0020015,
    #[error("SEC: Signature size invalid")]
    SigSizeInvalid = 0xc0020016,
    #[error("SEC: RSA PSS operation failed")]
    RsaPssOpFailed = 0xc0020017,
    #[error("SEC: Certificate authentication failed")]
    CertAuthFailed = 0xc0020018,
    #[error("SEC: Public key auth mismatch N size")]
    PubKeyAuthMismatchNSize = 0xc0020019,
    #[error("SEC: Public key auth mismatch E size")]
    PubKeyAuthMismatchESize = 0xc002001a,
    #[error("SEC: Public key auth mismatch N")]
    PubKeyAuthMismatchN = 0xc002001b,
    #[error("SEC: Public key auth mismatch E")]
    PubKeyAuthMismatchE = 0xc002001c,
    #[error("SEC: Public key auth mismatch hash")]
    PubKeyAuthMismatchHash = 0xc002001d,
    #[error("SEC: Certificate object not found")]
    CertObjNotFound = 0xc002001e,
    #[error("SEC: Certificate OID not found")]
    CertOidNotFound = 0xc002001f,
    #[error("SEC: Certificate out of range")]
    CertOutOfRange = 0xc0020020,
    #[error("SEC: OID doesn't match")]
    OidDoesntMatch = 0xc0020021,
    #[error("SEC: Length doesn't match")]
    LengthDoesntMatch = 0xc0020022,
    #[error("SEC: ASN1 unknown operation")]
    Asn1UnknownOp = 0xc0020023,
    #[error("SEC: OID index out of range")]
    OidIndexOutOfRange = 0xc0020024,
    #[error("SEC: OID too large")]
    OidTooLarge = 0xc0020025,
    #[error("SEC: Public key size mismatch")]
    PubKeySizeMismatch = 0xc0020026,
    #[error("SEC: SWID mismatch")]
    SwidMismatch = 0xc0020027,
    #[error("SEC: Hash size mismatch")]
    HashSizeMismatch = 0xc0020028,
    #[error("SEC: Image header type mismatch")]
    ImghdrTypeMismatch = 0xc0020029,
    #[error("SEC: Image type mismatch")]
    ImgTypeMismatch = 0xc002002a,
    #[error("SEC: Image header hash verify failed")]
    ImghdrHashVerifyFailed = 0xc002002b,
    #[error("SEC: Image hash verify failed")]
    ImgHashVerifyFailed = 0xc002002c,
    #[error("SEC: Anti rollback violation")]
    AntiRollbackViolation = 0xc002002d,
    #[error("SEC: SECCFG not found")]
    SeccfgNotFound = 0xc002002e,
    #[error("SEC: SECCFG magic is incorrect")]
    SeccfgMagicIncorrect = 0xc002002f,
    #[error("SEC: SECCFG is invalid")]
    SeccfgInvalid = 0xc0020030,
    #[error("SEC: Cipher mode is invalid")]
    CipherModeInvalid = 0xc0020031,
    #[error("SEC: Cipher key is invalid")]
    CipherKeyInvalid = 0xc0020032,
    #[error("SEC: Cipher data unaligned")]
    CipherDataUnaligned = 0xc0020033,
    #[error("SEC: GFH file info not found")]
    GfhFileInfoNotFound = 0xc0020034,
    #[error("SEC: GFH anti clone not found")]
    GfhAntiCloneNotFound = 0xc0020035,
    #[error("SEC: GFH sec config not found")]
    GfhSecCfgNotFound = 0xc0020036,
    #[error("SEC: Unsupported source type")]
    UnsupportedSourceType = 0xc0020037,
    #[error("SEC: Cust name mismatch")]
    CustNameMismatch = 0xc0020038,
    #[error("SEC: Invalid address")]
    InvalidAddress = 0xc0020039,
    #[error("SEC: Certificate version not synced")]
    CertificateVersionNotSynced = 0xc0020040,
    #[error("SEC: Signature not synced")]
    SignatureNotSynced = 0xc0020041,
    #[error("SEC: Ext AllInOne Signature rejected")]
    ExtAllInOneSignatureRejected = 0xc0020042,
    #[error("SEC: Ext AllInOne Signature missing")]
    ExtAllInOneSignatureMissing = 0xc0020043,
    #[error("SEC: Communication key is not set")]
    CommKeyIsNotSet = 0xc0020044,
    #[error("SEC: Device info check failed")]
    DevInfoCheckFailed = 0xc0020045,
    #[error("SEC: Boot image count overflow")]
    BootimgCountOverflow = 0xc0020046,
    #[error("SEC: Signature not found")]
    SignatureNotFound = 0xc0020047,
    #[error("SEC: Boot image special handle")]
    BootimgSpecialHandle = 0xc0020048,
    #[error("SEC: Remote security policy disabled")]
    RemoteSecurityPolicyDisabled = 0xc0020049,
    #[error("SEC: RSA OAEP failed")]
    RsaOaepFailed = 0xc002004A,
    #[error("SEC: Insufficient buffer")]
    InsufficientBuffer2 = 0xc002004B,
    #[error("SEC: DA Anti-Rollback error. DA version less than OTP version.")]
    DaAntiRollbackError = 0xc002004C,
    #[error("SEC: Get OTP value failed")]
    GetOtpValueFailed = 0xc002004D,
    #[error("SEC: Invalid unit size")]
    InvalidUnitSize = 0xc002004E,
    #[error("SEC: Invalid group index")]
    InvalidGroupIdx = 0xc002004F,
    #[error("SEC: Image version overflow")]
    ImgVersionOverflow = 0xc0020050,
    #[error("SEC: OTP table not initialized")]
    OtpTableNotInitialized = 0xc0020051,
    #[error("SEC: Invalid partition name")]
    InvalidPartitionName = 0xc0020052,
    #[error("SEC: DA version Anti-Rollback error")]
    DaVersionAntiRollbackError = 0xc0020053,
    #[error("SEC: Invalid message size")]
    InvalidMsgSize = 0xc0020054,
    #[error("SEC: Security level unsupported")]
    SecurityLevelUnsupported = 0xc0020055,
    #[error("SEC: Security level mismatch")]
    SecurityLevelMismatch = 0xc0020056,
    #[error("SEC: Fault injection error")]
    FaultInjectionError = 0xc0020057,
    #[error("SEC: Public key hash group is invalid.")]
    PubKeyHashGroupInvalid = 0xc0020058,
    #[error("SEC: Security level too large")]
    SecurityLevelTooLarge = 0xc0020059,
    #[error("SEC: Security config is formatted")]
    SecurityConfigIsFormatted = 0xc002005a,
    #[error("SEC: Security config unknown error")]
    SecurityConfigUnknownError = 0xc002005b,
    #[error("SEC: Failed getting seccfg lockstate")]
    LockstateSeccfgFailed = 0xc002005c,
    #[error("SEC: Failed getting custom lockstate")]
    LockstateCustomFailed = 0xc002005d,
    #[error("SEC: Lockstate is inconsistent")]
    LockstateInconsistent = 0xc002005e,

    // Library
    #[error("Library: Scatter file invalid")]
    ScatterFileInvalid = 0xc0030001,
    #[error("Library: DA file invalid")]
    DaFileInvalid = 0xc0030002,
    #[error("Library: DA selection error")]
    DaSelectionError = 0xc0030003,
    #[error("Library: Preloader invalid")]
    PreloaderInvalid = 0xc0030004,
    #[error("Library: EMI header invalid")]
    EmiHdrInvalid = 0xc0030005,
    #[error("Library: Storage mismatch")]
    StorageMismatch = 0xc0030006,
    #[error("Library: Invalid parameters")]
    InvalidParameters = 0xc0030007,
    #[error("Library: Invalid GPT")]
    InvalidGpt = 0xc0030008,
    #[error("Library: Invalid PMT")]
    InvalidPmt = 0xc0030009,
    #[error("Library: Layout changed")]
    LayoutChanged = 0xc003000a,
    #[error("Library: Invalid format parameter")]
    InvalidFormatParam = 0xc003000b,
    #[error("Library: Unknown storage section type")]
    UnknownStorageSectionType = 0xc003000c,
    #[error("Library: Unknown scatter field")]
    UnknownScatterField = 0xc003000d,
    #[error("Library: Partition table doesn't exist")]
    PartitionTblDoesntExist = 0xc003000e,
    #[error("Library: Scatter HW chip ID mismatch")]
    ScatterHwChipIdMismatch = 0xc003000f,
    #[error("Library: SEC certificate file not found")]
    SecCertFileNotFound = 0xc0030010,
    #[error("Library: SEC authentication file not found")]
    SecAuthFileNotFound = 0xc0030011,
    #[error("Library: SEC authentication file needed")]
    SecAuthFileNeeded = 0xc0030012,
    #[error("Library: EMI container file not found")]
    EmiContainerFileNotFound = 0xc0030013,
    #[error("Library: Scatter file not found")]
    ScatterFileNotFound = 0xc0030014,
    #[error("Library: XML file operation error")]
    XmlFileOpError = 0xc0030015,
    #[error("Library: Unsupported page size")]
    UnsupportedPageSize = 0xc0030016,
    #[error("Library: EMI info length offset invalid")]
    EmiInfoLengthOffsetInvalid = 0xc0030017,
    #[error("Library: EMI info length invalid")]
    EmiInfoLengthInvalid = 0xc0030018,

    // Device (Storage, DRAM, eFuses)
    #[error("Device: Unsupported operation")]
    UnsupportedOperation = 0xc0040001,
    #[error("Device: Thread error")]
    ThreadError = 0xc0040002,
    #[error("Device: Checksum error")]
    ChecksumError = 0xc0040003,
    #[error("Device: Unknown sparse image format")]
    UnknownSparse = 0xc0040004,
    #[error("Device: Unknown sparse chunk type")]
    UnknownSparseChunkType = 0xc0040005,
    #[error("Device: Partition not found")]
    PartitionNotFound = 0xc0040006,
    #[error("Device: Failed to read partition table")]
    ReadParttblFailed = 0xc0040007,
    #[error("Device: Exceeded maximum partition number")]
    ExceededMaxPartitionNumber = 0xc0040008,
    #[error("Device: Unknown storage type")]
    UnknownStorageType = 0xc0040009,
    #[error("Device: DRAM test failed")]
    DramTestFailed = 0xc004000A,
    #[error("Device: Exceeded available range")]
    ExceedAvailableRange = 0xc004000b,
    #[error("Device: Failed to write sparse image")]
    WriteSparseImageFailed = 0xc004000c,
    #[error("Device: MMC error")]
    MmcError = 0xc0040030,
    #[error("Device: NAND error")]
    NandError = 0xc0040040,
    #[error("Device: NAND operation in progress")]
    NandInProgress = 0xc0040041,
    #[error("Device: NAND timeout")]
    NandTimeout = 0xc0040042,
    #[error("Device: NAND bad block")]
    NandBadBlock = 0xc0040043,
    #[error("Device: NAND erase failed")]
    NandEraseFailed = 0xc0040044,
    #[error("Device: NAND page program failed")]
    NandPageProgramFailed = 0xc0040045,
    #[error("Device: EMI setting version error")]
    EmiSettingVersionError = 0xc0040050,
    #[error("Device: UFS error")]
    UfsError = 0xc0040060,
    #[error("Device: DA OTP not supported")]
    DaOtpNotSupported = 0xc0040100,
    #[error("Device: DA OTP lock failed")]
    DaOtpLockFailed = 0xc0040102,

    // eFuses
    #[error("eFuse: Unknown error")]
    EfuseUnknownError = 0xc0040200,
    #[error("eFuse: Write timeout without verification")]
    EfuseWriteTimeoutWithoutVerify = 0xc0040201,
    #[error("eFuse: fuse blown")]
    EfuseBlown = 0xc0040202,
    #[error("eFuse: Revert bit is set")]
    EfuseRevertBit = 0xc0040203,
    #[error("eFuse: fuse is partly blown, needs to be blown again")]
    EfuseBlownPartly = 0xc0040204,
    #[error("eFuse: argument is invalid")]
    EfuseInvalidArgument = 0xc0040205,
    #[error("eFuse: fuse value is not zero")]
    EfuseValueIsNotZero = 0xc0040206,
    #[error("eFuse: fuse blown with incorrect data")]
    EfuseBlownIncorrectData = 0xc0040207,
    #[error("eFuse: Fuse is broken")]
    EfuseBroken = 0xc0040208,
    #[error("eFuse: Eror during blow operation")]
    EfuseBlowError = 0xc0040209,
    #[error("eFuse: Error while unlocking BPKEY")]
    EfuseUnlockBpkeyError = 0xc004020A,
    #[error("eFuse: Failed to create list")]
    EfuseCreateListError = 0xc004020B,
    #[error("eFuse: Failed to write to register")]
    EfuseWriteRegisterError = 0xc004020C,
    #[error("eFuse: Padding type mismatch")]
    EfusePaddingTypeMismatch = 0xc004020D,

    // Host commands
    #[error("Host: Device control exception")]
    DeviceCtrlException = 0xc0050001,
    #[error("Host: Shutdown command exception")]
    ShutdownCmdException = 0xc0050002,
    #[error("Host: Download exception")]
    DownloadException = 0xc0050003,
    #[error("Host: Upload exception")]
    UploadException = 0xc0050004,
    #[error("Host: External RAM exception")]
    ExtRamException = 0xc0050005,
    #[error("Host: Notify switch USB speed exception")]
    NotifySwitchUsbSpeedException = 0xc0050006,
    #[error("Host: Read data exception")]
    ReadDataException = 0xc0050007,
    #[error("Host: Write data exception")]
    WriteDataException = 0xc0050008,
    #[error("Host: Format exception")]
    FormatException = 0xc0050009,
    #[error("Host: OTP operation exception")]
    OtpOperationException = 0xc005000A,
    #[error("Host: Switch USB exception")]
    SwitchUsbException = 0xc005000B,
    #[error("Host: Write eFuse exception")]
    WriteEfuseException = 0xc005000C,
    #[error("Host: Read eFuse exception")]
    ReadEfuseException = 0xc005000D,

    // BROM
    #[error("BROM: Start command failed")]
    BromStartCmdFailed = 0xc0060001,
    #[error("BROM: Failed to get BBChip HW version")]
    BromGetBbchipHwVerFailed = 0xc0060002,
    #[error("BROM: Send DA command failed")]
    BromCmdSendDaFailed = 0xc0060003,
    #[error("BROM: Failed to jump to DA")]
    BromCmdJumpDaFailed = 0xc0060004,
    #[error("BROM: Command failed")]
    BromCmdFailed = 0xc0060005,
    #[error("BROM: Stage callback failed")]
    BromStageCallbackFailed = 0xc0060006,

    // DA section
    #[error("DA: Version mismatch")]
    DaVersionMismatch = 0xc0070001,
    #[error("DA: Not found")]
    DaNotFound = 0xc0070002,
    #[error("DA: Section not found")]
    DaSectionNotFound = 0xc0070003,
    #[error("DA: Hash mismatch. DA2 hash does not match hash in DA1")]
    DaHashMismatch = 0xc0070004,
    #[error("DA: Exceeded maximum allowed number")]
    DaExceedMaxNum = 0xc0070005,

    #[error("Unknown error")]
    Unknown = 0xffffffff,
}

#[derive(Debug, Error)]
#[error("{kind} (code: {code:#010x})")]
pub struct XFlashError {
    pub kind: XFlashErrorKind,
    pub code: u32,
}

impl XFlashError {
    pub fn from_code(code: u32) -> Self {
        let kind = XFlashErrorKind::try_from(code).unwrap_or(XFlashErrorKind::Unknown);
        Self { kind, code }
    }
}
