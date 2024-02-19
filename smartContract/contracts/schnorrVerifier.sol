// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;



/**
 * SchnorrVerifier:
 *  this contract is used to verify the signatures signed using Schnorrs signature scheme
 *  @dev ECrecover is generally used to verify ECdsa signatures in general but this contract uses
 *  Ecrecover in a hacky way to verify signatures for Schnorrs
 *
 *  Ecrecover used for EcDsa
 *  ecrecover (bytes32 hash, uint8 v, bytes32 r, bytes32 s)
 *  R = f(r , v)
 *  1. a = -G * h
 *  2. b = R * s
 *
 *  we know for Ecdsa Sig verification
 *  r = (r*PubKey + h*G) / (s)
 *  PubKey = (s*r - h*G) / r
 *
 *  3. PubKey * r = s*R - h*G
 *                = b + a
 *  4. PubKey = (a + b) / R
 * 
 *  @notice For prod use to avoid replay attack add chainId and other chainSpecific data while computing MessageHashE
 */
contract SchnorrVerifier {
    // Ec Group N
    uint256 constant N =
        115792089237316195423570985008687907852837564279074904382605163141518161494337;


    /**
     * TRICK used to fool ecrecover
     * 1. Compute r using [G , S , PubKeyX , MessageHashE]
     * 2. derive MessageHashE' from [r , pubKeyX , Message]
     * 3. verify MessageHashE' == MessageHashE
     * 
     * how to compute r ? for schnorrs
     * we know,
     *  r = (G * s - P * e)
     *  
     * redefining ecRecover
     * ecrecover(-s*Px, v, Px, -e*Px)
     * 0. P = f(args[2], args[1])
     * 1. a = -G * (args[0]) == -s*Px*G
     * 2. b = args[2] * args[3] == P * -e * Px
     * 3. Q = (a + b) / args[2] == (-s*Px*G + P * -e * Px) / px
     *      = (Px (-s*G + P * -e)) / Px
     *      = -s*G + P * -e == r
     * e' = hash(addr(r) || parity || r || message)
     * return e == e'
     */
    function VerifySignature(
        bytes32 Pub_X,
        uint8 PubKeyParity,
        bytes32 MessageHashE, // e
        bytes32 SchnorrSig,
        bytes calldata Message
    ) public pure returns (bool) {
        bytes32 Sig_Pub_X = bytes32(
            N - mulmod(uint(SchnorrSig), uint(Pub_X), N)
        );
        uint8 PubKey_Parity = (PubKeyParity == 0 || PubKeyParity == 1)
            ? PubKeyParity + 27
            : (PubKeyParity);
        
        bytes32 Hash_Pub_X = bytes32(
            N - mulmod(uint(MessageHashE), uint(Pub_X), N)
        );
        address r = verify(Sig_Pub_X, PubKey_Parity, Pub_X, Hash_Pub_X);

        // compute e = hash(addr(r) || parity || r || message)
        bytes32 e = keccak256(abi.encodePacked(r, PubKey_Parity, Pub_X, Message));

        return e == MessageHashE;
    }
    function verify(
        bytes32 Sig_Pub_X, // hash (-s * Px)
        uint8 PubKey_Parity, // v (0 or 1 || 27 or 28)
        bytes32 Pub_X, // r (Px)
        bytes32 Hash_Pub_X // s (-e * Px)
    ) internal pure returns (address R) {
        R = ecrecover(Sig_Pub_X, PubKey_Parity, Pub_X, Hash_Pub_X);
    }
}
