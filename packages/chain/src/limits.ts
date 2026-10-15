/** Maximum serialized native transaction size accepted for broadcast.
 * Hex encoding doubles the HTTP payload; Bitcoin transport has its own limit.
 */
export const MAX_BROADCAST_BYTES = 2 * 1024 * 1024;
