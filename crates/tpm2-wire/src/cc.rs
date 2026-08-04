// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! `TPM_CC`: TPM 2.0 command codes.
//!
//! Transcribed by hand from `docs/tpm2-protocol-commands.md`, not derived at
//! build time. This is the daemon's security-relevant allow-list (see
//! `docs/design.md`) -- check changes against the TPM 2.0 Part 2 command
//! code table, don't hand-guess.

use crate::error::Error;

/// A TPM 2.0 command code (`TPM_CC_*`).
///
/// Variant names drop the `TPM_CC_`/`TPM2_ACT_` prefix and follow Rust's
/// `UpperCamelCase` convention for the rest (e.g. `TPM_CC_NV_Write` ->
/// `NvWrite`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u32)]
#[non_exhaustive]
pub enum TpmCc {
    NvUndefineSpaceSpecial = 287,     // 0x0000011f
    EvictControl = 288,               // 0x00000120
    HierarchyControl = 289,           // 0x00000121
    NvUndefineSpace = 290,            // 0x00000122
    ChangeEps = 292,                  // 0x00000124
    ChangePps = 293,                  // 0x00000125
    Clear = 294,                      // 0x00000126
    ClearControl = 295,               // 0x00000127
    ClockSet = 296,                   // 0x00000128
    HierarchyChangeAuth = 297,        // 0x00000129
    NvDefineSpace = 298,              // 0x0000012a
    PcrAllocate = 299,                // 0x0000012b
    PcrSetAuthPolicy = 300,           // 0x0000012c
    PpCommands = 301,                 // 0x0000012d
    SetPrimaryPolicy = 302,           // 0x0000012e
    FieldUpgradeStart = 303,          // 0x0000012f
    ClockRateAdjust = 304,            // 0x00000130
    CreatePrimary = 305,              // 0x00000131
    NvGlobalWriteLock = 306,          // 0x00000132
    GetCommandAuditDigest = 307,      // 0x00000133
    NvIncrement = 308,                // 0x00000134
    NvSetBits = 309,                  // 0x00000135
    NvExtend = 310,                   // 0x00000136
    NvWrite = 311,                    // 0x00000137
    NvWriteLock = 312,                // 0x00000138
    DictionaryAttackLockReset = 313,  // 0x00000139
    DictionaryAttackParameters = 314, // 0x0000013a
    NvChangeAuth = 315,               // 0x0000013b
    PcrEvent = 316,                   // 0x0000013c
    PcrReset = 317,                   // 0x0000013d
    SequenceComplete = 318,           // 0x0000013e
    SetAlgorithmSet = 319,            // 0x0000013f
    SetCommandCodeAuditStatus = 320,  // 0x00000140
    FieldUpgradeData = 321,           // 0x00000141
    IncrementalSelfTest = 322,        // 0x00000142
    SelfTest = 323,                   // 0x00000143
    Startup = 324,                    // 0x00000144
    Shutdown = 325,                   // 0x00000145
    StirRandom = 326,                 // 0x00000146
    ActivateCredential = 327,         // 0x00000147
    Certify = 328,                    // 0x00000148
    PolicyNv = 329,                   // 0x00000149
    CertifyCreation = 330,            // 0x0000014a
    Duplicate = 331,                  // 0x0000014b
    GetTime = 332,                    // 0x0000014c
    GetSessionAuditDigest = 333,      // 0x0000014d
    NvRead = 334,                     // 0x0000014e
    NvReadLock = 335,                 // 0x0000014f
    ObjectChangeAuth = 336,           // 0x00000150
    PolicySecret = 337,               // 0x00000151
    Rewrap = 338,                     // 0x00000152
    Create = 339,                     // 0x00000153
    EcdhZGen = 340,                   // 0x00000154
    Hmac = 341,                       // 0x00000155
    Import = 342,                     // 0x00000156
    Load = 343,                       // 0x00000157
    Quote = 344,                      // 0x00000158
    RsaDecrypt = 345,                 // 0x00000159
    HmacStart = 347,                  // 0x0000015b
    SequenceUpdate = 348,             // 0x0000015c
    Sign = 349,                       // 0x0000015d
    Unseal = 350,                     // 0x0000015e
    PolicySigned = 352,               // 0x00000160
    ContextLoad = 353,                // 0x00000161
    ContextSave = 354,                // 0x00000162
    EcdhKeyGen = 355,                 // 0x00000163
    EncryptDecrypt = 356,             // 0x00000164
    FlushContext = 357,               // 0x00000165
    LoadExternal = 359,               // 0x00000167
    MakeCredential = 360,             // 0x00000168
    NvReadPublic = 361,               // 0x00000169
    PolicyAuthorize = 362,            // 0x0000016a
    PolicyAuthValue = 363,            // 0x0000016b
    PolicyCommandCode = 364,          // 0x0000016c
    PolicyCounterTimer = 365,         // 0x0000016d
    PolicyCpHash = 366,               // 0x0000016e
    PolicyLocality = 367,             // 0x0000016f
    PolicyNameHash = 368,             // 0x00000170
    PolicyOr = 369,                   // 0x00000171
    PolicyTicket = 370,               // 0x00000172
    ReadPublic = 371,                 // 0x00000173
    RsaEncrypt = 372,                 // 0x00000174
    StartAuthSession = 374,           // 0x00000176
    VerifySignature = 375,            // 0x00000177
    EccParameters = 376,              // 0x00000178
    FirmwareRead = 377,               // 0x00000179
    GetCapability = 378,              // 0x0000017a
    GetRandom = 379,                  // 0x0000017b
    GetTestResult = 380,              // 0x0000017c
    Hash = 381,                       // 0x0000017d
    PcrRead = 382,                    // 0x0000017e
    PolicyPcr = 383,                  // 0x0000017f
    PolicyRestart = 384,              // 0x00000180
    ReadClock = 385,                  // 0x00000181
    PcrExtend = 386,                  // 0x00000182
    PcrSetAuthValue = 387,            // 0x00000183
    NvCertify = 388,                  // 0x00000184
    EventSequenceComplete = 389,      // 0x00000185
    HashSequenceStart = 390,          // 0x00000186
    PolicyPhysicalPresence = 391,     // 0x00000187
    PolicyDuplicationSelect = 392,    // 0x00000188
    PolicyGetDigest = 393,            // 0x00000189
    TestParms = 394,                  // 0x0000018a
    Commit = 395,                     // 0x0000018b
    PolicyPassword = 396,             // 0x0000018c
    ZGen2Phase = 397,                 // 0x0000018d
    EcEphemeral = 398,                // 0x0000018e
    PolicyNvWritten = 399,            // 0x0000018f
    PolicyTemplate = 400,             // 0x00000190
    CreateLoaded = 401,               // 0x00000191
    PolicyAuthorizeNv = 402,          // 0x00000192
    EncryptDecrypt2 = 403,            // 0x00000193
    AcGetCapability = 404,            // 0x00000194
    AcSend = 405,                     // 0x00000195
    PolicyAcSendSelect = 406,         // 0x00000196
    ActSetTimeout = 408,              // 0x00000198
    EccEncrypt = 409,                 // 0x00000199
    EccDecrypt = 410,                 // 0x0000019a
    PolicyCapability = 411,           // 0x0000019b
    PolicyParameters = 412,           // 0x0000019c
    NvDefineSpace2 = 413,             // 0x0000019d
    NvReadPublic2 = 414,              // 0x0000019e
    SetCapability = 415,              // 0x0000019f
    ReadOnlyControl = 416,            // 0x000001a0
    PolicyTransportSpdm = 417,        // 0x000001a1
    VendorTcgTest = 536870912,        // 0x20000000
}

impl TpmCc {
    /// Every recognized command code, in strictly increasing `value()` order.
    ///
    /// [`TpmCc::try_from`] binary-searches this list, so keep any future
    /// additions in increasing order.
    pub const ALL: &'static [TpmCc] = &[
        TpmCc::NvUndefineSpaceSpecial,
        TpmCc::EvictControl,
        TpmCc::HierarchyControl,
        TpmCc::NvUndefineSpace,
        TpmCc::ChangeEps,
        TpmCc::ChangePps,
        TpmCc::Clear,
        TpmCc::ClearControl,
        TpmCc::ClockSet,
        TpmCc::HierarchyChangeAuth,
        TpmCc::NvDefineSpace,
        TpmCc::PcrAllocate,
        TpmCc::PcrSetAuthPolicy,
        TpmCc::PpCommands,
        TpmCc::SetPrimaryPolicy,
        TpmCc::FieldUpgradeStart,
        TpmCc::ClockRateAdjust,
        TpmCc::CreatePrimary,
        TpmCc::NvGlobalWriteLock,
        TpmCc::GetCommandAuditDigest,
        TpmCc::NvIncrement,
        TpmCc::NvSetBits,
        TpmCc::NvExtend,
        TpmCc::NvWrite,
        TpmCc::NvWriteLock,
        TpmCc::DictionaryAttackLockReset,
        TpmCc::DictionaryAttackParameters,
        TpmCc::NvChangeAuth,
        TpmCc::PcrEvent,
        TpmCc::PcrReset,
        TpmCc::SequenceComplete,
        TpmCc::SetAlgorithmSet,
        TpmCc::SetCommandCodeAuditStatus,
        TpmCc::FieldUpgradeData,
        TpmCc::IncrementalSelfTest,
        TpmCc::SelfTest,
        TpmCc::Startup,
        TpmCc::Shutdown,
        TpmCc::StirRandom,
        TpmCc::ActivateCredential,
        TpmCc::Certify,
        TpmCc::PolicyNv,
        TpmCc::CertifyCreation,
        TpmCc::Duplicate,
        TpmCc::GetTime,
        TpmCc::GetSessionAuditDigest,
        TpmCc::NvRead,
        TpmCc::NvReadLock,
        TpmCc::ObjectChangeAuth,
        TpmCc::PolicySecret,
        TpmCc::Rewrap,
        TpmCc::Create,
        TpmCc::EcdhZGen,
        TpmCc::Hmac,
        TpmCc::Import,
        TpmCc::Load,
        TpmCc::Quote,
        TpmCc::RsaDecrypt,
        TpmCc::HmacStart,
        TpmCc::SequenceUpdate,
        TpmCc::Sign,
        TpmCc::Unseal,
        TpmCc::PolicySigned,
        TpmCc::ContextLoad,
        TpmCc::ContextSave,
        TpmCc::EcdhKeyGen,
        TpmCc::EncryptDecrypt,
        TpmCc::FlushContext,
        TpmCc::LoadExternal,
        TpmCc::MakeCredential,
        TpmCc::NvReadPublic,
        TpmCc::PolicyAuthorize,
        TpmCc::PolicyAuthValue,
        TpmCc::PolicyCommandCode,
        TpmCc::PolicyCounterTimer,
        TpmCc::PolicyCpHash,
        TpmCc::PolicyLocality,
        TpmCc::PolicyNameHash,
        TpmCc::PolicyOr,
        TpmCc::PolicyTicket,
        TpmCc::ReadPublic,
        TpmCc::RsaEncrypt,
        TpmCc::StartAuthSession,
        TpmCc::VerifySignature,
        TpmCc::EccParameters,
        TpmCc::FirmwareRead,
        TpmCc::GetCapability,
        TpmCc::GetRandom,
        TpmCc::GetTestResult,
        TpmCc::Hash,
        TpmCc::PcrRead,
        TpmCc::PolicyPcr,
        TpmCc::PolicyRestart,
        TpmCc::ReadClock,
        TpmCc::PcrExtend,
        TpmCc::PcrSetAuthValue,
        TpmCc::NvCertify,
        TpmCc::EventSequenceComplete,
        TpmCc::HashSequenceStart,
        TpmCc::PolicyPhysicalPresence,
        TpmCc::PolicyDuplicationSelect,
        TpmCc::PolicyGetDigest,
        TpmCc::TestParms,
        TpmCc::Commit,
        TpmCc::PolicyPassword,
        TpmCc::ZGen2Phase,
        TpmCc::EcEphemeral,
        TpmCc::PolicyNvWritten,
        TpmCc::PolicyTemplate,
        TpmCc::CreateLoaded,
        TpmCc::PolicyAuthorizeNv,
        TpmCc::EncryptDecrypt2,
        TpmCc::AcGetCapability,
        TpmCc::AcSend,
        TpmCc::PolicyAcSendSelect,
        TpmCc::ActSetTimeout,
        TpmCc::EccEncrypt,
        TpmCc::EccDecrypt,
        TpmCc::PolicyCapability,
        TpmCc::PolicyParameters,
        TpmCc::NvDefineSpace2,
        TpmCc::NvReadPublic2,
        TpmCc::SetCapability,
        TpmCc::ReadOnlyControl,
        TpmCc::PolicyTransportSpdm,
        TpmCc::VendorTcgTest,
    ];

    /// The raw `u32` command code value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self as u32
    }

    /// The number of handles this command carries in its handle area.
    ///
    /// Spec-defined, fixed per command; needed to split every recognized
    /// command's handle area from its parameters, even ones without a typed
    /// [`crate::commands::CommandBody`] decoder.
    #[must_use]
    pub const fn handle_count(self) -> u8 {
        match self {
            TpmCc::NvUndefineSpaceSpecial => 2,
            TpmCc::EvictControl => 2,
            TpmCc::HierarchyControl => 1,
            TpmCc::NvUndefineSpace => 2,
            TpmCc::ChangeEps => 1,
            TpmCc::ChangePps => 1,
            TpmCc::Clear => 1,
            TpmCc::ClearControl => 1,
            TpmCc::ClockSet => 1,
            TpmCc::HierarchyChangeAuth => 1,
            TpmCc::NvDefineSpace => 1,
            TpmCc::PcrAllocate => 1,
            TpmCc::PcrSetAuthPolicy => 1,
            TpmCc::PpCommands => 1,
            TpmCc::SetPrimaryPolicy => 1,
            TpmCc::FieldUpgradeStart => 2,
            TpmCc::ClockRateAdjust => 1,
            TpmCc::CreatePrimary => 1,
            TpmCc::NvGlobalWriteLock => 1,
            TpmCc::GetCommandAuditDigest => 2,
            TpmCc::NvIncrement => 2,
            TpmCc::NvSetBits => 2,
            TpmCc::NvExtend => 2,
            TpmCc::NvWrite => 2,
            TpmCc::NvWriteLock => 2,
            TpmCc::DictionaryAttackLockReset => 1,
            TpmCc::DictionaryAttackParameters => 1,
            TpmCc::NvChangeAuth => 1,
            TpmCc::PcrEvent => 1,
            TpmCc::PcrReset => 1,
            TpmCc::SequenceComplete => 1,
            TpmCc::SetAlgorithmSet => 1,
            TpmCc::SetCommandCodeAuditStatus => 1,
            TpmCc::FieldUpgradeData => 0,
            TpmCc::IncrementalSelfTest => 0,
            TpmCc::SelfTest => 0,
            TpmCc::Startup => 0,
            TpmCc::Shutdown => 0,
            TpmCc::StirRandom => 0,
            TpmCc::ActivateCredential => 2,
            TpmCc::Certify => 2,
            TpmCc::PolicyNv => 3,
            TpmCc::CertifyCreation => 2,
            TpmCc::Duplicate => 2,
            TpmCc::GetTime => 2,
            TpmCc::GetSessionAuditDigest => 3,
            TpmCc::NvRead => 2,
            TpmCc::NvReadLock => 2,
            TpmCc::ObjectChangeAuth => 2,
            TpmCc::PolicySecret => 2,
            TpmCc::Rewrap => 2,
            TpmCc::Create => 1,
            TpmCc::EcdhZGen => 1,
            TpmCc::Hmac => 1,
            TpmCc::Import => 1,
            TpmCc::Load => 1,
            TpmCc::Quote => 1,
            TpmCc::RsaDecrypt => 1,
            TpmCc::HmacStart => 1,
            TpmCc::SequenceUpdate => 1,
            TpmCc::Sign => 1,
            TpmCc::Unseal => 1,
            TpmCc::PolicySigned => 2,
            TpmCc::ContextLoad => 0,
            TpmCc::ContextSave => 1,
            TpmCc::EcdhKeyGen => 1,
            TpmCc::EncryptDecrypt => 1,
            TpmCc::FlushContext => 0,
            TpmCc::LoadExternal => 0,
            TpmCc::MakeCredential => 1,
            TpmCc::NvReadPublic => 1,
            TpmCc::PolicyAuthorize => 1,
            TpmCc::PolicyAuthValue => 1,
            TpmCc::PolicyCommandCode => 1,
            TpmCc::PolicyCounterTimer => 1,
            TpmCc::PolicyCpHash => 1,
            TpmCc::PolicyLocality => 1,
            TpmCc::PolicyNameHash => 1,
            TpmCc::PolicyOr => 1,
            TpmCc::PolicyTicket => 1,
            TpmCc::ReadPublic => 1,
            TpmCc::RsaEncrypt => 1,
            TpmCc::StartAuthSession => 2,
            TpmCc::VerifySignature => 1,
            TpmCc::EccParameters => 0,
            TpmCc::FirmwareRead => 0,
            TpmCc::GetCapability => 0,
            TpmCc::GetRandom => 0,
            TpmCc::GetTestResult => 0,
            TpmCc::Hash => 0,
            TpmCc::PcrRead => 0,
            TpmCc::PolicyPcr => 1,
            TpmCc::PolicyRestart => 1,
            TpmCc::ReadClock => 0,
            TpmCc::PcrExtend => 1,
            TpmCc::PcrSetAuthValue => 1,
            TpmCc::NvCertify => 3,
            TpmCc::EventSequenceComplete => 2,
            TpmCc::HashSequenceStart => 0,
            TpmCc::PolicyPhysicalPresence => 1,
            TpmCc::PolicyDuplicationSelect => 1,
            TpmCc::PolicyGetDigest => 1,
            TpmCc::TestParms => 0,
            TpmCc::Commit => 1,
            TpmCc::PolicyPassword => 1,
            TpmCc::ZGen2Phase => 1,
            TpmCc::EcEphemeral => 0,
            TpmCc::PolicyNvWritten => 1,
            TpmCc::PolicyTemplate => 1,
            TpmCc::CreateLoaded => 1,
            TpmCc::PolicyAuthorizeNv => 3,
            TpmCc::EncryptDecrypt2 => 1,
            TpmCc::AcGetCapability => 1,
            TpmCc::AcSend => 3,
            TpmCc::PolicyAcSendSelect => 1,
            TpmCc::ActSetTimeout => 1,
            TpmCc::EccEncrypt => 1,
            TpmCc::EccDecrypt => 1,
            TpmCc::PolicyCapability => 1,
            TpmCc::PolicyParameters => 1,
            TpmCc::NvDefineSpace2 => 1,
            TpmCc::NvReadPublic2 => 1,
            TpmCc::SetCapability => 1,
            TpmCc::ReadOnlyControl => 1,
            TpmCc::PolicyTransportSpdm => 1,
            TpmCc::VendorTcgTest => 0,
        }
    }
}

impl TryFrom<u32> for TpmCc {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Error> {
        Self::ALL
            .binary_search_by_key(&value, |cc| cc.value())
            .map(|index| Self::ALL[index])
            .map_err(|_| Error::UnknownCommandCode(value))
    }
}

impl core::fmt::Display for TpmCc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?} ({:#010x})", self.value())
    }
}
