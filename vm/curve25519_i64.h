#ifndef CURVE25519_I64_H
#define CURVE25519_I64_H 1

/* Generic 64-bit integer implementation of Curve25519 ECDH
 * Written by Matthijs van Duin, 200608242056
 * Public domain.
 *
 * Based on work by Daniel J Bernstein, http://cr.yp.to/ecdh.html
 */

#include <stddef.h>

typedef unsigned char k25519[32]; /* any type of key */

extern const k25519 zero25519;	/* 0 */
extern const k25519 prime25519;	/* the prime 2^255-19 */
extern const k25519 order25519;	/* group order (a prime near 2^252+2^124) */

typedef k25519 pub25519;	/* public key */
typedef k25519 priv25519;	/* private key (for key agreement) */
typedef k25519 spriv25519;	/* private key for signing */
typedef k25519 sec25519;	/* shared secret */


//Internal, do not use.
void core25519(k25519 Px, k25519 s, const k25519 k, const k25519 Gx);

/********* KEY AGREEMENT *********/

/* Private key clamping
 *   k [out] your private key for key agreement
 *   k  [in]  32 random bytes
 */
static inline
void clamp25519(priv25519 k) {
	k[31] &= 0x7F;
	k[31] |= 0x40;
	k[ 0] &= 0xF8;
}

/* Key-pair generation
 *   P  [out] your public key
 *   s  [out] your private key for signing
 *   k  [out] your private key for key agreement
 *   k  [in]  32 random bytes
 * s may be NULL if you don't care
 *
 * WARNING: if s is not NULL, this function has data-dependent timing */
static inline
void keygen25519(pub25519 P, spriv25519 s, priv25519 k) {
	clamp25519(k);
	core25519(P, s, k, NULL);
}


/* Key agreement
 *   Z  [out] shared secret (needs hashing before use)
 *   k  [in]  your private key for key agreement
 *   P  [in]  peer's public key
 * Buffers may overlap.  */
static inline
void curve25519(sec25519 Z, const priv25519 k, const pub25519 P) {
	core25519(Z, NULL, k, P);
}


int sign25519(k25519 v, const k25519 h, const priv25519 x, const spriv25519 s);


/* Signature verification primitive, calculates Y = vP + hG
 *   Y  [out] signature public key
 *   v  [in]  signature value
 *   h  [in]  signature hash
 *   P  [in]  public key
 */
void verify25519(pub25519 Y, const k25519 v, const k25519 h, const pub25519 P);


#endif
