use "libs/secp256k1/secp256k1";

use "libs/crypto/hash/keccak256";
use "libs/crypto/hmac";
use "libs/crypto/drbg/hmac_drbg";
use "libs/crypto/drbg/drbg";

signature KEY_PAIR =
sig
  exception Fail of string

  type keyPair;

  val getPrivateKey : keyPair -> Word8Vector.vector
  val getPublicKey : keyPair -> Word8Vector.vector

  val fromPrivateKey : Word8Vector.vector -> keyPair
  val random : unit -> keyPair

  val signMessage : keyPair -> Word8Vector.vector ->
    {r: Word8VectorSlice.vector, recid: int, s: Word8VectorSlice.vector}
end

structure KeyPair :> KEY_PAIR =
struct
  exception Fail of string

  type privkey = Word8Vector.vector
  type pubkey = Word8Vector.vector

  datatype keyPair = KeyPair of privkey * pubkey

  fun getPrivateKey (KeyPair (privkey, _)) = privkey
  fun getPublicKey (KeyPair (_, pubkey)) = pubkey

(*  fun create (privkey, pubkey) =
  let
    val _ = Secp256k1.start()
    val isPrivkeyValid = Secp256k1.ecdsaPrivkeyVerify privkey
    val isPubkeyValid = Secp256k1.ecdsaPubkeyVerify pubkey
  in
    if isPrivkeyValid
    then
      let
        val correspondingPubkey = Secp256k1.ecdsaPubkeyCreate privkey
      in
        if correspondingPubkey = pubkey
        then KeyPair(privkey, pubkey)
        else raise Fail "Key pair is not valid"
      end
    else raise Fail "Key pair is not valid"
  end *)

  fun fromPrivateKey privkey =
  let
    val _ = Secp256k1.start()
    val pubkey = (Secp256k1.ecdsaPubkeyCreate privkey false)
      handle Secp256k1.Secp256k1 ex => raise Fail ex
    (* val _ = Secp256k1.stop() - stopping inside the function may cause another function fail *)
  in
    KeyPair (privkey, pubkey)
  end

  local
    structure Rand = Drbg(HmacDrbg(Hmac(Keccak256)))
    val rand = Rand.instantiate(NONE)
  in
    fun random () =
    let
      val _ = Secp256k1.start()
      fun getPrivateKey () =
      let (* TODO: add exception handling of random generation *)
        val privkey = Rand.generate(rand, 32, false, NONE)
      in  (* ensure that generated private key is valid *)
        if Secp256k1.ecdsaPrivkeyVerify privkey
        then privkey
        else getPrivateKey ()
      end

      val privkey = getPrivateKey ()
    in
       (* should not raise as private key was verified *)
      fromPrivateKey privkey
    end
  end

  (* fun load (path) *)


  local
    structure Keccak256HmacDrbg = HmacDrbg(Hmac(Keccak256))
  in
    fun signMessage keyPair msg =
    let
      val nonceLen = 32
      val emptyVec = Word8Array.vector (Word8Array.array(nonceLen, 0w0))
      val msgHash = Keccak256.hash msg

      val drbg = Keccak256HmacDrbg.instantiate (privkey, msgHash, emptyVec)
      fun getNonce drbg =
      let
        val nonce = Keccak256HmacDrbg.generate (drbg, nonceLen, emptyVec)
      in
         (* TODO: we have to check that generated nonce is less than order of
         *   G of the Secp256k1 used *)
        if nonce <> emptyVec
        then nonce
        else getNonce drbg
      end
      val nonce = getNonce drbg

      val privkey = getPrivateKey keyPair

      val _ = Secp256k1.start()
       (* Secp256k1 exception may be raised. Have to think about handling it *)
      val sign = Secp256k1.ecdsaSignCompact privkey msgHash nonce
      val _ = Secp256k1.stop()
    in
      sign
    end
  end


end
