// Feature flags — capabilities gated behind a process-wide switch.
//
// Schnorr (algo id 2): the node supports it but doesn't use it by default. The
// wallet ships the complete signing/verification foundation (schnorr.ts). The
// implementation is confirmed BIP-340-compliant against the node's own module,
// so the app now enables SIGNING at startup (src/main enables it via setSchnorrEnabled(true)).
// Verification is deliberately NOT gated — incoming network data may already carry Schnorr
// signatures regardless of whether we sign with it.
//
// The default here stays OFF so the primitive can be exercised in isolation
// (tests opt in explicitly); the running app flips it on once at startup. The
// flag is process-wide and not meant to be toggled at runtime.

let schnorrEnabled = false;

/** True if Schnorr SIGNING (and offering it at key import) is enabled. */
export function isSchnorrEnabled(): boolean {
  return schnorrEnabled;
}

/** Enable/disable Schnorr signing. Call once at app startup. */
export function setSchnorrEnabled(enabled: boolean): void {
  schnorrEnabled = enabled;
}

/** Thrown when a Schnorr signing path is hit while the flag is off. */
export class SchnorrDisabledError extends Error {
  override readonly name = 'SchnorrDisabledError';
  constructor() {
    super(
      'Schnorr signing is implemented but not enabled yet (setSchnorrEnabled).',
    );
  }
}
