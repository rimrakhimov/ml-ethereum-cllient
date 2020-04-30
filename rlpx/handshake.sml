use "libs/crypto/kdf/concatKDF";
use "libs/crypto/hash/keccak256";
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
    structure Rand = Drbg(HmacDrbg(Hmac(Keccak256)))
    val rand = Rand.instantiate(NONE)
  in
    (* fun createHandshake (staticKeyPair : KeyPair.keyPair, remotePublicKey) = *)
    fun createHandshake () =
    let
      val staticKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wxb7, 0wx4a, 0wx3e, 0wxc3, 0wxd9, 0wx41, 0wx45, 0wxc0,
          0wx3d, 0wxd7, 0wx8a, 0wx75, 0wx3a, 0wxf4, 0wxcf, 0wx22,
          0wx48, 0wxfe, 0wx92, 0wx7b, 0wx28, 0wx65, 0wxae, 0wx3b,
          0wxb2, 0wx85, 0wxd2, 0wx0b, 0wx30, 0wx06, 0wx6d, 0wx5d
        ]
      )

      val remotePublicKey = Word8Vector.fromList [
        0wx04, 0wxc7, 0wx7f, 0wxb5, 0wxb6, 0wxe3, 0wx4d, 0wx79,
        0wxe3, 0wx97, 0wx2d, 0wx13, 0wxc4, 0wx75, 0wx43, 0wxa3,
        0wx4c, 0wx00, 0wx7c, 0wxbd, 0wxe0, 0wx77, 0wx41, 0wx79,
        0wxeb, 0wx1c, 0wx36, 0wx4b, 0wxda, 0wx2d, 0wxd0, 0wx65,
        0wxab, 0wxb2, 0wx2d, 0wx0f, 0wx59, 0wx06, 0wx65, 0wx80,
        0wx79, 0wx73, 0wx97, 0wx9d, 0wxa8, 0wx84, 0wx9b, 0wxd0,
        0wx52, 0wx4e, 0wxfe, 0wx95, 0wx6c, 0wxbd, 0wx28, 0wxa7,
        0wxf8, 0wxef, 0wxae, 0wx77, 0wxc8, 0wx50, 0wxa0, 0wx9a,
        0wx36
      ]

      (* val nonce = Rand.generate(rand, 32, false, NONE)
      val ephemeralKeyPair = KeyPair.random() *)
      val nonce = Word8Vector.fromList [
        0wx64, 0wxe6, 0wx4f, 0wx7b, 0wxfe, 0wx4e, 0wx38, 0wx60,
        0wxf3, 0wx99, 0wx24, 0wx38, 0wx95, 0wxaf, 0wxfd, 0wx5a,
        0wx6d, 0wx92, 0wx99, 0wxa7, 0wx02, 0wx06, 0wx19, 0wx48,
        0wxbc, 0wxb0, 0wx28, 0wx26, 0wx03, 0wxee, 0wxe3, 0wx39
      ]

      val ephemeralKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wxfc, 0wxa1, 0wxd2, 0wx11, 0wx55, 0wx17, 0wx13, 0wxf2,
          0wx76, 0wx19, 0wx50, 0wxd6, 0wx33, 0wx41, 0wx8e, 0wx14,
          0wx2c, 0wxb5, 0wxfc, 0wx80, 0wx66, 0wx4c, 0wxfa, 0wx68,
          0wx22, 0wx54, 0wx1e, 0wx7a, 0wx20, 0wxeb, 0wxc4, 0wx21
        ]
      )

      val staticSharedSecret = computeSharedSecret (
        KeyPair.getPrivateKey staticKeyPair, remotePublicKey
      )

      val toSign = Utils.word8VectorXorb (staticSharedSecret, nonce)
    in
      KeyPair.signMessage ephemeralKeyPair toSign
    end
  end

  end
