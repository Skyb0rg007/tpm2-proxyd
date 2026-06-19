<!--
SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>

SPDX-License-Identifier: BSD-2-Clause
-->

# TPM2 Commands Recognized by tpm2-protocol

This table tracks the `TpmCc` enum in
`references/tpm2-protocol/src/data/enum/mod.rs`. These are the TPM command
codes that `tpm2-proxyd` can parse as recognized commands through
`tpm2_protocol::data::TpmCc`.

| Command | Decimal ID | Hex ID | Description |
| --- | ---: | ---: | --- |
| `TPM_CC_NV_UndefineSpaceSpecial` | 287 | `0x0000011F` | Removes an NV index using platform authorization with special index attributes. |
| `TPM_CC_EvictControl` | 288 | `0x00000120` | Makes a transient object persistent or evicts a persistent object. |
| `TPM_CC_HierarchyControl` | 289 | `0x00000121` | Enables or disables TPM hierarchies. |
| `TPM_CC_NV_UndefineSpace` | 290 | `0x00000122` | Deletes an NV index using its normal authorization path. |
| `TPM_CC_ChangeEPS` | 292 | `0x00000124` | Changes the endorsement primary seed. |
| `TPM_CC_ChangePPS` | 293 | `0x00000125` | Changes the platform primary seed. |
| `TPM_CC_Clear` | 294 | `0x00000126` | Resets owner-controlled TPM state and authorization values. |
| `TPM_CC_ClearControl` | 295 | `0x00000127` | Enables or disables use of `TPM_CC_Clear`. |
| `TPM_CC_ClockSet` | 296 | `0x00000128` | Sets the TPM clock value. |
| `TPM_CC_HierarchyChangeAuth` | 297 | `0x00000129` | Changes the authorization value for a hierarchy. |
| `TPM_CC_NV_DefineSpace` | 298 | `0x0000012A` | Creates an NV index with caller-specified attributes and authorization. |
| `TPM_CC_PCR_Allocate` | 299 | `0x0000012B` | Allocates PCR banks for selected hash algorithms. |
| `TPM_CC_PCR_SetAuthPolicy` | 300 | `0x0000012C` | Sets an authorization policy for a PCR. |
| `TPM_CC_PP_Commands` | 301 | `0x0000012D` | Changes which commands require physical presence. |
| `TPM_CC_SetPrimaryPolicy` | 302 | `0x0000012E` | Sets the policy controlling primary-object creation in a hierarchy. |
| `TPM_CC_FieldUpgradeStart` | 303 | `0x0000012F` | Starts a TPM firmware field-upgrade sequence. |
| `TPM_CC_ClockRateAdjust` | 304 | `0x00000130` | Adjusts the TPM clock rate. |
| `TPM_CC_CreatePrimary` | 305 | `0x00000131` | Creates a primary object under a hierarchy. |
| `TPM_CC_NV_GlobalWriteLock` | 306 | `0x00000132` | Locks writes to all NV indexes that honor the global write lock. |
| `TPM_CC_GetCommandAuditDigest` | 307 | `0x00000133` | Returns an attested digest of audited commands. |
| `TPM_CC_NV_Increment` | 308 | `0x00000134` | Increments an NV counter index. |
| `TPM_CC_NV_SetBits` | 309 | `0x00000135` | Sets bits in a bit-field NV index. |
| `TPM_CC_NV_Extend` | 310 | `0x00000136` | Extends digest data into an extend-type NV index. |
| `TPM_CC_NV_Write` | 311 | `0x00000137` | Writes data to an NV index. |
| `TPM_CC_NV_WriteLock` | 312 | `0x00000138` | Locks further writes to an NV index. |
| `TPM_CC_DictionaryAttackLockReset` | 313 | `0x00000139` | Resets dictionary-attack lockout state. |
| `TPM_CC_DictionaryAttackParameters` | 314 | `0x0000013A` | Configures dictionary-attack lockout limits and recovery times. |
| `TPM_CC_NV_ChangeAuth` | 315 | `0x0000013B` | Changes the authorization value for an NV index. |
| `TPM_CC_PCR_Event` | 316 | `0x0000013C` | Extends event data into a PCR and returns computed digests. |
| `TPM_CC_PCR_Reset` | 317 | `0x0000013D` | Resets a resettable PCR to its initial value. |
| `TPM_CC_SequenceComplete` | 318 | `0x0000013E` | Completes a hash or HMAC sequence and returns the result. |
| `TPM_CC_SetAlgorithmSet` | 319 | `0x0000013F` | Selects an algorithm set supported by the TPM. |
| `TPM_CC_SetCommandCodeAuditStatus` | 320 | `0x00000140` | Changes which command codes are included in command audit. |
| `TPM_CC_FieldUpgradeData` | 321 | `0x00000141` | Sends a block of field-upgrade data to the TPM. |
| `TPM_CC_IncrementalSelfTest` | 322 | `0x00000142` | Runs self-tests for selected algorithms. |
| `TPM_CC_SelfTest` | 323 | `0x00000143` | Runs TPM self-tests. |
| `TPM_CC_Startup` | 324 | `0x00000144` | Starts the TPM for a clear or state-preserving boot. |
| `TPM_CC_Shutdown` | 325 | `0x00000145` | Prepares the TPM for shutdown. |
| `TPM_CC_StirRandom` | 326 | `0x00000146` | Mixes caller-provided entropy into the TPM random generator. |
| `TPM_CC_ActivateCredential` | 327 | `0x00000147` | Proves an object is loaded by decrypting an activation credential. |
| `TPM_CC_Certify` | 328 | `0x00000148` | Produces an attestation over an object's name and qualified name. |
| `TPM_CC_PolicyNV` | 329 | `0x00000149` | Adds an NV comparison assertion to a policy digest. |
| `TPM_CC_CertifyCreation` | 330 | `0x0000014A` | Attests that an object was created with specific creation data. |
| `TPM_CC_Duplicate` | 331 | `0x0000014B` | Exports a duplicated object for import under another parent. |
| `TPM_CC_GetTime` | 332 | `0x0000014C` | Returns a signed attestation of TPM time. |
| `TPM_CC_GetSessionAuditDigest` | 333 | `0x0000014D` | Returns an attested digest of an audited session. |
| `TPM_CC_NV_Read` | 334 | `0x0000014E` | Reads data from an NV index. |
| `TPM_CC_NV_ReadLock` | 335 | `0x0000014F` | Locks further reads from an NV index. |
| `TPM_CC_ObjectChangeAuth` | 336 | `0x00000150` | Changes an object's authorization value and returns a new private blob. |
| `TPM_CC_PolicySecret` | 337 | `0x00000151` | Adds proof of knowledge of an entity's auth value to a policy. |
| `TPM_CC_Rewrap` | 338 | `0x00000152` | Re-encrypts duplicate data from an old parent to a new parent. |
| `TPM_CC_Create` | 339 | `0x00000153` | Creates a child object under a loaded parent. |
| `TPM_CC_ECDH_ZGen` | 340 | `0x00000154` | Computes an ECDH shared secret with a loaded ECC key. |
| `TPM_CC_HMAC` | 341 | `0x00000155` | Computes an HMAC with a loaded keyed-hash object. |
| `TPM_CC_Import` | 342 | `0x00000156` | Imports a duplicated object under a loaded parent. |
| `TPM_CC_Load` | 343 | `0x00000157` | Loads a private/public object pair under a parent. |
| `TPM_CC_Quote` | 344 | `0x00000158` | Produces a signed attestation over selected PCR values. |
| `TPM_CC_RSA_Decrypt` | 345 | `0x00000159` | Decrypts data with a loaded RSA key. |
| `TPM_CC_HMAC_Start` | 347 | `0x0000015B` | Starts a multi-part HMAC sequence. |
| `TPM_CC_SequenceUpdate` | 348 | `0x0000015C` | Adds data to an active hash, HMAC, or event sequence. |
| `TPM_CC_Sign` | 349 | `0x0000015D` | Signs a digest with a loaded signing key. |
| `TPM_CC_Unseal` | 350 | `0x0000015E` | Returns the sensitive data sealed in a loaded object. |
| `TPM_CC_PolicySigned` | 352 | `0x00000160` | Adds a signature-based authorization assertion to a policy. |
| `TPM_CC_ContextLoad` | 353 | `0x00000161` | Loads a saved object or session context. |
| `TPM_CC_ContextSave` | 354 | `0x00000162` | Saves an object or session context for later reload. |
| `TPM_CC_ECDH_KeyGen` | 355 | `0x00000163` | Generates an ephemeral ECC point and ECDH shared secret. |
| `TPM_CC_EncryptDecrypt` | 356 | `0x00000164` | Encrypts or decrypts data with a symmetric key object. |
| `TPM_CC_FlushContext` | 357 | `0x00000165` | Removes a loaded object, sequence, or session from TPM memory. |
| `TPM_CC_LoadExternal` | 359 | `0x00000167` | Loads an external public or private object into the TPM. |
| `TPM_CC_MakeCredential` | 360 | `0x00000168` | Creates a credential encrypted to a loaded object's name. |
| `TPM_CC_NV_ReadPublic` | 361 | `0x00000169` | Reads public metadata for an NV index. |
| `TPM_CC_PolicyAuthorize` | 362 | `0x0000016A` | Replaces a policy digest after authorization by an approved signing key. |
| `TPM_CC_PolicyAuthValue` | 363 | `0x0000016B` | Requires object authorization to satisfy the policy. |
| `TPM_CC_PolicyCommandCode` | 364 | `0x0000016C` | Restricts a policy session to a specific command code. |
| `TPM_CC_PolicyCounterTimer` | 365 | `0x0000016D` | Adds a clock or counter comparison assertion to a policy. |
| `TPM_CC_PolicyCpHash` | 366 | `0x0000016E` | Restricts a policy session to command parameters with a specific cpHash. |
| `TPM_CC_PolicyLocality` | 367 | `0x0000016F` | Restricts a policy session to specific TPM localities. |
| `TPM_CC_PolicyNameHash` | 368 | `0x00000170` | Restricts a policy session to a digest of command object names. |
| `TPM_CC_PolicyOr` | 369 | `0x00000171` | Allows any one of several policy digests to satisfy a policy. |
| `TPM_CC_PolicyTicket` | 370 | `0x00000172` | Adds validation of a TPM ticket to a policy. |
| `TPM_CC_ReadPublic` | 371 | `0x00000173` | Reads public data and names for a loaded object. |
| `TPM_CC_RSA_Encrypt` | 372 | `0x00000174` | Encrypts data with an RSA public key. |
| `TPM_CC_StartAuthSession` | 374 | `0x00000176` | Starts an HMAC, policy, or trial authorization session. |
| `TPM_CC_VerifySignature` | 375 | `0x00000177` | Verifies a signature with a loaded public key. |
| `TPM_CC_ECC_Parameters` | 376 | `0x00000178` | Returns parameters for an ECC curve. |
| `TPM_CC_FirmwareRead` | 377 | `0x00000179` | Reads firmware data during field upgrade. |
| `TPM_CC_GetCapability` | 378 | `0x0000017A` | Queries TPM capabilities and property data. |
| `TPM_CC_GetRandom` | 379 | `0x0000017B` | Returns random bytes from the TPM random generator. |
| `TPM_CC_GetTestResult` | 380 | `0x0000017C` | Returns TPM self-test result data. |
| `TPM_CC_Hash` | 381 | `0x0000017D` | Hashes a buffer and returns the digest and validation ticket. |
| `TPM_CC_PCR_Read` | 382 | `0x0000017E` | Reads selected PCR values and update counter. |
| `TPM_CC_PolicyPCR` | 383 | `0x0000017F` | Adds selected PCR values to a policy digest. |
| `TPM_CC_PolicyRestart` | 384 | `0x00000180` | Resets a policy session to its initial digest. |
| `TPM_CC_ReadClock` | 385 | `0x00000181` | Reads TPM clock and reset/restart counters. |
| `TPM_CC_PCR_Extend` | 386 | `0x00000182` | Extends digests into a PCR. |
| `TPM_CC_PCR_SetAuthValue` | 387 | `0x00000183` | Sets a PCR authorization value. |
| `TPM_CC_NV_Certify` | 388 | `0x00000184` | Produces an attestation over NV index contents. |
| `TPM_CC_EventSequenceComplete` | 389 | `0x00000185` | Completes an event sequence and extends resulting digests into a PCR. |
| `TPM_CC_HashSequenceStart` | 390 | `0x00000186` | Starts a multi-part hash or event sequence. |
| `TPM_CC_PolicyPhysicalPresence` | 391 | `0x00000187` | Requires physical presence for a policy session. |
| `TPM_CC_PolicyDuplicationSelect` | 392 | `0x00000188` | Restricts object duplication to selected names. |
| `TPM_CC_PolicyGetDigest` | 393 | `0x00000189` | Returns the current digest of a policy session. |
| `TPM_CC_TestParms` | 394 | `0x0000018A` | Tests whether algorithm parameters are supported. |
| `TPM_CC_Commit` | 395 | `0x0000018B` | Performs the ECC commit operation used by signature schemes. |
| `TPM_CC_PolicyPassword` | 396 | `0x0000018C` | Requires password authorization to satisfy the policy. |
| `TPM_CC_ZGen_2Phase` | 397 | `0x0000018D` | Computes the second phase of ECC key exchange. |
| `TPM_CC_EC_Ephemeral` | 398 | `0x0000018E` | Generates an ephemeral ECC point for a selected curve. |
| `TPM_CC_PolicyNvWritten` | 399 | `0x0000018F` | Requires an NV index written-state condition in a policy. |
| `TPM_CC_PolicyTemplate` | 400 | `0x00000190` | Restricts object creation to a specific public template digest. |
| `TPM_CC_CreateLoaded` | 401 | `0x00000191` | Creates an object and returns it already loaded. |
| `TPM_CC_PolicyAuthorizeNV` | 402 | `0x00000192` | Authorizes a policy using data from an NV index. |
| `TPM_CC_EncryptDecrypt2` | 403 | `0x00000193` | Encrypts or decrypts data with an alternate parameter order. |
| `TPM_CC_AcGetCapability` | 404 | `0x00000194` | Queries capabilities of attached components. |
| `TPM_CC_AcSend` | 405 | `0x00000195` | Sends a TPM-mediated command to an attached component. |
| `TPM_CC_Policy_AC_SendSelect` | 406 | `0x00000196` | Restricts policy use of attached-component send operations. |
| `TPM2_ACT_SetTimeout` | 408 | `0x00000198` | Sets the timeout value for an attached-component timer. |
| `TPM_CC_ECC_Encrypt` | 409 | `0x00000199` | Encrypts data using an ECC key agreement scheme. |
| `TPM_CC_ECC_Decrypt` | 410 | `0x0000019A` | Decrypts data using an ECC key agreement scheme. |
| `TPM_CC_PolicyCapability` | 411 | `0x0000019B` | Adds a capability-data assertion to a policy digest. |
| `TPM_CC_PolicyParameters` | 412 | `0x0000019C` | Restricts a policy session to selected command parameters. |
| `TPM_CC_NV_DefineSpace2` | 413 | `0x0000019D` | Defines an NV index using the TPM 2.0 revision 1.83 form. |
| `TPM_CC_NV_ReadPublic2` | 414 | `0x0000019E` | Reads public NV metadata using the TPM 2.0 revision 1.83 form. |
| `TPM_CC_SetCapability` | 415 | `0x0000019F` | Sets a TPM capability value where supported. |
| `TPM_CC_ReadOnlyControl` | 416 | `0x000001A0` | Controls the TPM read-only state where supported. |
| `TPM_CC_Policy_TransportSPDM` | 417 | `0x000001A1` | Adds SPDM transport binding information to a policy digest. |
| `TPM_CC_Vendor_TCG_Test` | 536870912 | `0x20000000` | TCG-reserved vendor test command. |
