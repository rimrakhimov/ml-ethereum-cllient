use "libs/crypto/kdf/concatKDF";
use "libs/crypto/hash/keccak256";
use "libs/crypto/hash/sha256";
use "libs/secp256k1/secp256k1";
use "libs/crypto/hmac";
use "libs/crypto/drbg/drbg";
use "libs/crypto/drbg/hmac_drbg";
use "utils";
use "keyPair";
use "libs/random/random";

structure Handshake =
struct
  structure Hash = Keccak256
  structure Secp256k1 = Secp256k1

  fun computeSharedSecret (privkey, pubkey) =
  let
    fun internal () =
      Utils.takeVectorSlice (
        Secp256k1.ecdsaPubkeyMul pubkey  privkey, 1, SOME 32
      )
  in
    internal ()
     (* if Secp256k1 has not been started yet, start and try again *)
    handle Fail ex => (
      Secp256k1.start();
      internal ()
    )
  end

  local
    structure Kdf = ConcatKDF(Hash)
  in
    fun deriveKeyMaterials (localPrivkey, remotePubkey) =
    let
      val sharedSecret = computeSharedSecret (localPrivkey, remotePubkey)
      val keyMaterial = Kdf.kdf (sharedSecret, 32, Word8Vector.fromList [])

      val encKey = Utils.takeVectorSlice (keyMaterial, 0, SOME 16)
      val authKey = Utils.takeVectorSlice (keyMaterial, 16, SOME 16)
    in
      {encKey = encKey, authKey = authKey}
    end
  end

  local
    structure Sha256HmacDrbg = HmacDrbg(Hmac(Sha256))
  in
    fun sign_rfc6979 privkey msg =
    let
      val nonceLen = 32
      val emptyVec = Word8Vector.fromList []

      val drbg = Sha256HmacDrbg.instantiate (privkey, msg, emptyVec)
      fun getNonce drbg =
      let
        val zeroNonce = Word8Array.vector (Word8Array.array(nonceLen, 0w0))
        val nonce = Sha256HmacDrbg.generate (drbg, nonceLen, emptyVec)
      in
       (* TODO: we have to check that generated nonce is less than order of
        *   G of the Secp256k1 used *)
        if nonce <> zeroNonce
        then nonce
        else getNonce drbg
      end
      val nonce = getNonce drbg

      val _ = Secp256k1.start()
       (* Secp256k1 exception may be raised. Have to think about handling it *)
      val sign = Secp256k1.ecdsaSignCompact privkey msg nonce
    in
      sign
    end
  end

  local
    structure Rand = Drbg(HmacDrbg(Hmac(Keccak256)))
    val rand = Rand.instantiate(NONE)
  in
    (* fun createHandshake (staticKeyPair : KeyPair.keyPair, remotePublicKey) = *)
    fun createHandshake () =
    let
      val staticKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wx57, 0wx43, 0wx8f, 0wx3c, 0wx56, 0wx35, 0wxa9, 0wx91,
          0wxce, 0wxa3, 0wxb7, 0wx0e, 0wx3e, 0wx1e, 0wx8c, 0wx46,
          0wxb4, 0wx1d, 0wx41, 0wx91, 0wx78, 0wx9b, 0wx18, 0wxc5,
          0wx20, 0wx84, 0wxff, 0wx08, 0wx2a, 0wx8d, 0wxff, 0wx25
        ]
      )

      val remotePublicKey = Word8Vector.fromList [
        0wx04, 0wxec, 0wxdd, 0wxcc, 0wx4e, 0wx6a, 0wx97, 0wx23,
        0wxad, 0wx07, 0wx29, 0wx5b, 0wx8c, 0wxf8, 0wx48, 0wx73,
        0wxe8, 0wx44, 0wxcf, 0wxde, 0wx6b, 0wxaa, 0wx74, 0wx66,
        0wxbf, 0wxf0, 0wxac, 0wxc3, 0wx3c, 0wx9e, 0wx03, 0wx4f,
        0wxa6, 0wx13, 0wx7d, 0wx2b, 0wxa0, 0wx0e, 0wx01, 0wx60,
        0wx60, 0wx26, 0wxda, 0wx66, 0wxd8, 0wx70, 0wx87, 0wx5c,
        0wx2b, 0wxd3, 0wxfe, 0wx54, 0wx4c, 0wxd1, 0wx52, 0wxf5,
        0wx5f, 0wxf1, 0wx47, 0wxb5, 0wxf7, 0wx5c, 0wx25, 0wx66,
        0wxc2
      ]

      (* val nonce = Rand.generate(rand, 32, false, NONE)
      val ephemeralKeyPair = KeyPair.random() *)
      val nonce = Word8Vector.fromList [
        0wx0e, 0wx21, 0wx53, 0wxb7, 0wxee, 0wx72, 0wxe3, 0wx5a,
        0wxe4, 0wxc4, 0wx26, 0wx95, 0wxc0, 0wxd9, 0wx7b, 0wxa8,
        0wx54, 0wx52, 0wxe6, 0wxf9, 0wx6b, 0wx37, 0wx69, 0wxe2,
        0wxec, 0wx3a, 0wxc9, 0wxd7, 0wx98, 0wx8a, 0wx5a, 0wx4f
      ]

      val ephemeralKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wxea, 0wx2b, 0wxf8, 0wx1a, 0wx08, 0wxf2, 0wx43, 0wxb4,
          0wx79, 0wx80, 0wx65, 0wx54, 0wx14, 0wx7b, 0wx8e, 0wx4a,
          0wxa8, 0wx76, 0wxe3, 0wx14, 0wx72, 0wxef, 0wxf0, 0wx71,
          0wx9e, 0wx1f, 0wx58, 0wxca, 0wx8d, 0wx92, 0wxc1, 0wx92
        ]
      )

      val staticSharedSecret = computeSharedSecret (
        KeyPair.getPrivateKey staticKeyPair, remotePublicKey
      )

      val toSign = Utils.word8VectorXorb (staticSharedSecret, nonce)
    in
      sign_rfc6979 (KeyPair.getPrivateKey ephemeralKeyPair) toSign
    end
  end

  end
