// Public API of @qbtc/crypto.
//
// This file is intentionally small — it only re-exports stable primitives
// that consumers use. Internal helpers stay internal.
//
// The package ships no chain constants: chain-specific values (schemes, magic,
// HKDF labels, WIF versions, upgrade parameters) are injected by the
// consumer through a ChainProfile — see profile.ts and bindProfile().

// Chain profile — the per-chain value injection point.
export {
  bindProfile,
  validateProfile,
  type BoundChainCrypto,
  type ChainProfile,
  type WifVersionMap,
} from './profile';

// Encoding primitives.
export { fromHex, toHex } from './encoding/hex';
export {
  decodeVarint,
  encodeVarint,
  type VarintDecodeResult,
} from './encoding/varint';
export {
  decodeVarstr,
  encodeVarstr,
  type VarstrDecodeResult,
} from './encoding/varstr';
export {
  decodeBase58Check,
  encodeBase58Check,
  type Base58CheckDecodeResult,
} from './encoding/base58check';

// Hash primitives.
export {
  checksum32,
  hash160,
  hash256,
  ripemd160,
  sha256,
} from './hashes';

// BIP-39 mnemonics.
export {
  generateMnemonic,
  mnemonicToSeed,
  validateMnemonic,
  type MnemonicLength,
} from './bip39';

// BIP-32 HD derivation (secp256k1 branch). Scheme lists live in the
// consumer's ChainProfile; these helpers take them as parameters.
export {
  coinTypeFor,
  HARDENED,
  HDKey,
  activeScheme,
  derivePath,
  nativePathFor,
  legacySchemes,
  masterKeyFromSeed,
  requireScheme,
  schemeById,
  type DerivationScheme,
} from './bip32';

// secp256k1 primitives.
export {
  COMPRESSED_PUBLIC_KEY_BYTES,
  PRIVATE_KEY_BYTES,
  UNCOMPRESSED_PUBLIC_KEY_BYTES,
  getPublicKey,
  isValidPrivateKey,
  isValidPublicKey,
  sign,
  verify,
} from './secp256k1';

// Protocol constants (identical for every chain on the protocol).
export {
  ALGO_ID,
  ALGO_POSTQUANTUM_BIT,
  DENOMINATOR,
  SIGHASH,
  forkCommitsTokenId,
  isPostQuantum,
  type Algorithm,
  type Network,
  type DowngradeChainConfig,
  type UpgradeChainConfig,
} from './constants';

export {
  buildFreezeOutput,
  downgradeScript,
  federationFreezeScript,
  federationScripthash,
  freezeOutputData,
  freezeScript,
  reclaimCsvValue,
  reclaimIdFor,
  reclaimScripthash,
  signReclaimInput,
} from './downgrade';

// Script construction.
export {
  OP_CHECKSIG,
  OP_DUP,
  OP_EQUALVERIFY,
  OP_HASH160,
  OP_HASH256,
  OP_PUSHDATA1,
  OP_PUSHDATA2,
  OP_PUSHDATA4,
  opPushdata,
  scriptP2PK,
  scriptType,
  type ScriptType,
} from './script';

// Address encoding / decoding (magic/regex come from the ChainProfile).
export {
  addressFromPubkey,
  addressFromScripthash,
  decodeAddress,
  scripthashFromPubkey,
  validateAddress,
  type AddrMagic,
  type AddressRegex,
  type DecodedAddress,
} from './address';

// Account xpub — classical watch-only derivation (public CKD from an account key).
export {
  addressFromXpub,
  exportAccountXpubFor,
  isValidAccountXpub,
  parseAccountXpub,
} from './xpub';

// Encrypted vault primitives (KDF + AEAD).
export {
  CURRENT_KDF,
  DEFAULT_ARGON2ID_PARAMS,
  DEFAULT_SCRYPT_PARAMS,
  IV_BYTES,
  SALT_BYTES,
  VaultAuthError,
  VaultFormatError,
  deriveKey,
  sealVault,
  unsealVault,
  type Argon2idParams,
  type ScryptParams,
  type SealOptions,
  type VaultBlob,
} from './vault';

// App-data encryption (at-rest, key derived from the seed — for non-key data).
export {
  AppDataError,
  deriveAppDataKey,
  openAppData,
  sealAppData,
  type AppDataBlob,
} from './appData';

// Transaction model & serialization.
export {
  TOKEN_HASH_BYTES,
  TOKEN_TXO_TYPE_TRANSFER,
  TX_TYPE_STANDARD,
  TX_TYPE_TOKENS,
  deserialize,
  encodeTokenTransfer,
  serialize,
  serializeForSighash,
  sighash,
  txid,
  type Transaction,
  type TxInput,
  type TxOutput,
} from './transaction';

// Transaction signing.
export {
  decodeSiglistEntry,
  encodeSiglistEntry,
  signTransaction,
  signWithAlgorithm,
  verifySiglistEntry,
  type SigningInput,
} from './signing';

// Signed messages (canonical format; the magic comes from the ChainProfile).
export {
  signMessage,
  signedMessageDigest,
  signedMessagePreimage,
  verifyMessage,
} from './signedMessage';

// HD → Falcon-512 post-quantum derivation (purpose 512' branch).
export {
  PURPOSE_FALCON512,
  deriveFalconKeypair,
  nativePqPathFor,
} from './falconHd';

// Schnorr (BIP-340) primitives + the feature gate for offering it.
export {
  SCHNORR_PUBLIC_KEY_BYTES,
  SCHNORR_SIGNATURE_BYTES,
  isValidSchnorrPublicKey,
  schnorrGetPublicKey,
  schnorrSign,
  schnorrVerify,
} from './schnorr';
export {
  SchnorrDisabledError,
  isSchnorrEnabled,
  setSchnorrEnabled,
} from './features';

// WIF private-key import/export (node-compatible envelope).
export {
  FALCON512_KEYPAIR_BYTES,
  WifError,
  WifNetworkError,
  decodeWif,
  encodeWif,
  falconKeypairFromWifPayload,
  type DecodedWif,
} from './wif';

// Bitcoin addresses (upgrade flow: staging display + Return BTC decode).
export {
  bech32Encode,
  btcAddressFromScriptPubKey,
  btcP2pkhAddress,
  btcP2pkhAddressForPubkey,
  btcP2shAddress,
  decodeBtcAddress,
  toWords,
  type BtcAddressKind,
  type BtcNetwork,
  type DecodedBtcAddress,
} from './btc/address';

// The federated P2SH-P2WSH multisig (upgrade flow: the BTC lock address).
export {
  btcP2shP2wshMultisig,
  type BtcMultisigLock,
} from './btc/multisig';

// Bitcoin transaction construction (upgrade flow: staging → lock spend).
export {
  BTC_RBF_SEQUENCE,
  BTC_SIGHASH_ALL,
  btcSighashAll,
  btcTxid,
  estimateBtcP2pkhTxSize,
  scriptBtcOpReturn,
  scriptBtcP2pkh,
  scriptBtcP2pkhForPubkey,
  serializeBtcTx,
  signBtcP2pkhSpend,
  type BtcOutPoint,
  type BtcTransaction,
  type BtcTxInput,
  type BtcTxOutput,
  type UnsignedBtcSpend,
} from './btc/tx';

// Falcon-512 (WASM-backed once built).
export {
  FALCON512_PRIVATE_KEY_BYTES,
  FALCON512_PUBLIC_KEY_BYTES,
  FALCON512_SEED_BYTES,
  FALCON512_SIG_MAX_BYTES,
  Falcon512NotBuiltError,
  falcon512IsReady,
  falcon512KeygenFromSeed,
  falcon512Sign,
  falcon512Verify,
  setFalcon512WasmSource,
  type Falcon512Keypair,
  type Falcon512WasmSource,
} from './falcon512';
