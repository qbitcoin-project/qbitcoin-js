// ChainProfile — the injection point for every per-chain value.
//
// This package carries no chain constants: nothing in it knows which
// chain it is serving. A consumer declares its chain once, as a `ChainProfile`
// literal (schemes, address magic, WIF versions, HKDF labels, message
// magic, upgrade parameters), and either:
//
//   - passes individual values to the pure functions of the other
//     modules (they all take their chain values as explicit trailing
//     parameters), or
//   - calls `bindProfile(profile)` once and uses the returned facade,
//     which has the ergonomic zero-config signatures (active-scheme
//     defaults, no repeated magic/label arguments).
//
// There is deliberately NO global state: two profiles can coexist in one
// process (e.g. a tool bridging two chains), and nothing changes behavior
// at a distance.
//
// FROZEN-VALUE WARNING for consumers: everything in a shipped chain's
// profile except `upgrade` display parameters is consensus- or
// storage-affecting. Changing schemes, magic, HKDF labels, or WIF
// versions after shipping strands user funds or data. Guard your profile
// with pin tests in your own repo.

import {
  addressFromPubkey,
  addressFromScripthash,
  decodeAddress,
  validateAddress,
  type AddrMagic,
  type AddressRegex,
  type DecodedAddress,
} from './address.js';
import {
  activeScheme,
  legacySchemes,
  nativePathFor,
  requireScheme,
  schemeById,
  type DerivationScheme,
  type HDKey,
} from './bip32.js';
import {
  forkCommitsTokenId,
  type Algorithm,
  type DowngradeChainConfig,
  type Network,
  type UpgradeChainConfig,
} from './constants.js';
import { deriveAppDataKey } from './appData.js';
import { FALCON512_PUBLIC_KEY_BYTES, type Falcon512Keypair } from './falcon512.js';
import { deriveFalconKeypair, nativePqPathFor } from './falconHd.js';
import {
  signedMessageDigest,
  signedMessagePreimage,
  signMessage,
  verifyMessage,
} from './signedMessage.js';
import { decodeWif, encodeWif, type DecodedWif } from './wif.js';
import { addressFromXpub, exportAccountXpubFor } from './xpub.js';

/** Per-network one-byte WIF version prefixes (see `profile.wifVersion`). */
export type WifVersionMap = Readonly<Record<Network, number>>;

/**
 * Everything that makes a chain THIS chain, from the wallet-crypto
 * perspective. All fields are consensus- or storage-affecting unless
 * noted; see the header warning.
 */
export interface ChainProfile {
  /** Diagnostics-only label (error messages, logs). Not consensus. */
  readonly name: string;
  /**
   * Address magic prefix per network, prepended to the scripthash before
   * Base58Check encoding. Lengths may differ between networks — the
   * decoder always takes the length from here.
   */
  readonly addrMagic: AddrMagic;
  /**
   * Fast address-shape pre-filter per network. Kept as an explicit value
   * (not derived from `addrMagic` at runtime) so it can match the node's
   * own address regex byte for byte; pin it in your repo against the
   * node's constants.
   */
  readonly addressRegex: AddressRegex;
  /** One-byte WIF version per network (typically 0x80/0xEF). */
  readonly wifVersion: WifVersionMap;
  /**
   * Every derivation scheme the chain's wallets know about, in scan
   * priority order for funds discovery. Exactly ONE must have
   * `status: 'active'` — `bindProfile` enforces this.
   */
  readonly schemes: readonly DerivationScheme[];
  /**
   * The scheme that owns data persisted BEFORE storage became per-scheme
   * (wallet meta without a `schemes` map, version-1 watch descriptors):
   * whatever scheme was active when those formats were written. Must be
   * the id of one of `schemes`. When a chain adds a new active scheme,
   * this stays pointing at the ORIGINAL one.
   */
  readonly metaV1SchemeId: string;
  /**
   * HKDF `info` label of the Falcon-512 keygen-seed derivation
   * (falconHd.ts). Versioned; never change after shipping.
   */
  readonly falconHdInfo: string;
  /**
   * HKDF `info` label of the app-data encryption key (appData.ts).
   * Must differ from `falconHdInfo` — the two keys are domain-separated
   * by construction. Never change after shipping.
   */
  readonly appDataInfo: string;
  /**
   * Signed-message magic prefix (signedMessage.ts). Minimum 5 bytes so a
   * message digest can never collide with a transaction sighash.
   */
  readonly messageMagic: string;
  /**
   * BTC→native upgrade parameters per network, or null when the chain
   * has no Bitcoin upgrade path. Pass-through data: this package only
   * carries it to the consumer's upgrade logic.
   */
  readonly upgrade: Readonly<Record<Network, UpgradeChainConfig>> | null;
  /**
   * Native→BTC downgrade parameters per network, or null when the chain
   * has no downgrade flow. Pass-through data: the covenant builders in
   * downgrade.ts take these values as explicit parameters. The freeze
   * federation is 2-of-3, so exactly three Falcon-512 pubkeys.
   */
  readonly downgrade: Readonly<Record<Network, DowngradeChainConfig>> | null;
  /**
   * When transaction sign data starts committing the token id, per
   * network (unix seconds): `0` = since genesis, `null` = never. Must
   * mirror the chain node's fork schedule — `forkCommitsTokenId` in
   * constants.ts documents the exact semantics.
   */
  readonly tokenSighashFork: Readonly<Record<Network, number | null>>;
}

const NETWORKS: readonly Network[] = ['mainnet', 'testnet'];

/**
 * Validate a profile's internal consistency. Called by {@link bindProfile};
 * exported for consumers that want to fail fast in their own tests.
 * Throws with a descriptive message on the first violation.
 */
export function validateProfile(profile: ChainProfile): void {
  const where = `chain profile '${profile.name}'`;

  const actives = profile.schemes.filter((s) => s.status === 'active');
  if (actives.length !== 1) {
    throw new Error(
      `${where}: exactly one active derivation scheme required, found ${actives.length}`,
    );
  }
  const ids = new Set(profile.schemes.map((s) => s.id));
  if (ids.size !== profile.schemes.length) {
    throw new Error(`${where}: derivation scheme ids must be unique`);
  }
  if (!ids.has(profile.metaV1SchemeId)) {
    throw new Error(
      `${where}: metaV1SchemeId '${profile.metaV1SchemeId}' is not one of its schemes`,
    );
  }

  for (const network of NETWORKS) {
    if (profile.addrMagic[network].length === 0) {
      throw new Error(`${where}: ${network} address magic must not be empty`);
    }
    const wif = profile.wifVersion[network];
    if (!Number.isInteger(wif) || wif < 0 || wif > 0xff) {
      throw new Error(`${where}: ${network} WIF version must be one byte, got ${wif}`);
    }
  }
  if (profile.wifVersion.mainnet === profile.wifVersion.testnet) {
    throw new Error(
      `${where}: mainnet and testnet WIF versions must differ (the decoder tells networks apart by them)`,
    );
  }

  if (profile.falconHdInfo.length === 0 || profile.appDataInfo.length === 0) {
    throw new Error(`${where}: HKDF info labels must not be empty`);
  }
  if (profile.falconHdInfo === profile.appDataInfo) {
    throw new Error(
      `${where}: falconHdInfo and appDataInfo must differ (they domain-separate two keys of the same seed)`,
    );
  }

  if (profile.downgrade !== null) {
    for (const network of NETWORKS) {
      const d = profile.downgrade[network];
      if (d.freezePubkeysHex.length !== 3) {
        throw new Error(
          `${where}: ${network} freeze federation is 2-of-3 — exactly 3 pubkeys required, got ${d.freezePubkeysHex.length}`,
        );
      }
      for (const pk of d.freezePubkeysHex) {
        if (!isHexOfBytes(pk, FALCON512_PUBLIC_KEY_BYTES)) {
          throw new Error(
            `${where}: ${network} freeze pubkeys must be ${FALCON512_PUBLIC_KEY_BYTES}-byte hex Falcon-512 keys`,
          );
        }
      }
      if (!(d.freezeSeconds > 0) || !(d.outputSeconds > 0)) {
        throw new Error(`${where}: ${network} downgrade reclaim windows must be positive`);
      }
      if (d.legacyLockPubkeyHex !== undefined && !isHexOfBytes(d.legacyLockPubkeyHex, 33)) {
        throw new Error(
          `${where}: ${network} legacyLockPubkeyHex must be a 33-byte hex compressed pubkey`,
        );
      }
    }
  }

  for (const network of NETWORKS) {
    const fork = profile.tokenSighashFork[network];
    if (fork !== null && (!Number.isInteger(fork) || fork < 0)) {
      throw new Error(
        `${where}: ${network} tokenSighashFork must be null or a non-negative integer (unix seconds)`,
      );
    }
  }

  // 5+ bytes keeps varstr(magic) from ever starting like a valid tx_type
  // (1..4) — the signed-message/transaction domain separation.
  if (new TextEncoder().encode(profile.messageMagic).length < 5) {
    throw new Error(`${where}: messageMagic must be at least 5 bytes`);
  }
}

function isHexOfBytes(value: string, bytes: number): boolean {
  return value.length === bytes * 2 && /^[0-9a-fA-F]+$/.test(value);
}

/**
 * The profile-bound convenience API — the pure functions of this package
 * with every chain value pre-filled from one {@link ChainProfile}.
 * Consumers typically create one of these in a small facade module and
 * import it everywhere the unbound functions would need chain values.
 */
export interface BoundChainCrypto {
  /** The profile this facade was bound to. */
  readonly profile: ChainProfile;

  // Derivation schemes.
  activeScheme(): DerivationScheme;
  legacySchemes(): readonly DerivationScheme[];
  schemeById(id: string): DerivationScheme | undefined;
  requireScheme(id: string): DerivationScheme;
  readonly metaV1SchemeId: string;

  // Derivation paths (active scheme unless one is passed explicitly).
  nativePath(account: number, index: number, network: Network, change?: 0 | 1): string;
  nativePqPath(account: number, index: number, network: Network, change?: 0 | 1): string;
  deriveFalconKeypair(
    master: HDKey,
    account: number,
    change: 0 | 1,
    index: number,
    network: Network,
    scheme?: DerivationScheme,
  ): Promise<Falcon512Keypair>;
  exportAccountXpub(master: HDKey, network: Network, account?: number): string;

  // Addresses.
  addressFromScripthash(scripthash: Uint8Array, network: Network): string;
  addressFromPubkey(pubkey: Uint8Array, algo: Algorithm, network: Network): string;
  validateAddress(address: string, network: Network): boolean;
  decodeAddress(address: string): DecodedAddress;
  addressFromXpub(account: HDKey, chain: 0 | 1, index: number, network: Network): string;

  // WIF.
  encodeWif(payload: Uint8Array, network: Network): string;
  decodeWif(wif: string, network: Network): DecodedWif;

  // App-data key.
  deriveAppDataKey(masterSeed: Uint8Array): Uint8Array;

  // Signed messages.
  signedMessagePreimage(message: string): Uint8Array;
  signedMessageDigest(message: string): Uint8Array;
  signMessage(message: string, privateKey: Uint8Array, algo: Algorithm): Promise<Uint8Array>;
  verifyMessage(
    message: string,
    signature: Uint8Array,
    publicKey: Uint8Array,
    algo: Algorithm,
  ): Promise<boolean>;

  // Token-id sighash fork: whether a token-transfer signature produced at
  // `atSeconds` (default: now) must commit the token id on `network`.
  sighashCommitsTokenId(network: Network, atSeconds?: number): boolean;

  // Upgrade / downgrade parameters (pass-through; null when the chain has none).
  readonly upgrade: Readonly<Record<Network, UpgradeChainConfig>> | null;
  readonly downgrade: Readonly<Record<Network, DowngradeChainConfig>> | null;
}

/**
 * Bind a {@link ChainProfile} to the package's pure functions, returning
 * the zero-config facade. Validates the profile first (see
 * {@link validateProfile}) so a misconfigured chain fails at startup, not
 * at first use.
 */
export function bindProfile(profile: ChainProfile): BoundChainCrypto {
  validateProfile(profile);
  const { addrMagic, addressRegex, wifVersion, schemes } = profile;
  const active = () => activeScheme(schemes);

  return {
    profile,

    activeScheme: active,
    legacySchemes: () => legacySchemes(schemes),
    schemeById: (id) => schemeById(schemes, id),
    requireScheme: (id) => requireScheme(schemes, id),
    metaV1SchemeId: profile.metaV1SchemeId,

    nativePath: (account, index, network, change = 0) =>
      nativePathFor(active(), account, index, network, change),
    nativePqPath: (account, index, network, change = 0) =>
      nativePqPathFor(active(), account, index, network, change),
    deriveFalconKeypair: (master, account, change, index, network, scheme = active()) =>
      deriveFalconKeypair(master, account, change, index, network, scheme, profile.falconHdInfo),
    exportAccountXpub: (master, network, account = 0) =>
      exportAccountXpubFor(master, active(), network, account),

    addressFromScripthash: (scripthash, network) =>
      addressFromScripthash(scripthash, network, addrMagic),
    addressFromPubkey: (pubkey, algo, network) =>
      addressFromPubkey(pubkey, algo, network, addrMagic),
    validateAddress: (address, network) =>
      validateAddress(address, network, addrMagic, addressRegex),
    decodeAddress: (address) => decodeAddress(address, addrMagic, addressRegex),
    addressFromXpub: (account, chain, index, network) =>
      addressFromXpub(account, chain, index, network, addrMagic),

    encodeWif: (payload, network) => encodeWif(payload, network, wifVersion),
    decodeWif: (wif, network) => decodeWif(wif, network, wifVersion),

    deriveAppDataKey: (masterSeed) => deriveAppDataKey(masterSeed, profile.appDataInfo),

    signedMessagePreimage: (message) => signedMessagePreimage(message, profile.messageMagic),
    signedMessageDigest: (message) => signedMessageDigest(message, profile.messageMagic),
    signMessage: (message, privateKey, algo) =>
      signMessage(message, privateKey, algo, profile.messageMagic),
    verifyMessage: (message, signature, publicKey, algo) =>
      verifyMessage(message, signature, publicKey, algo, profile.messageMagic),

    sighashCommitsTokenId: (network, atSeconds = Math.floor(Date.now() / 1000)) =>
      forkCommitsTokenId(profile.tokenSighashFork[network], atSeconds),

    upgrade: profile.upgrade,
    downgrade: profile.downgrade,
  };
}
