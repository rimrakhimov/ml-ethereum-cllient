use "libs/crypto/kdf/concatKDF";
use "libs/crypto/hash/sha256";
use "libs/secp256k1/secp256k1";
use "libs/crypto/hmac";
use "libs/crypto/drbg/drbg";
use "libs/crypto/drbg/hmac_drbg";
use "utils";
use "keyPair";
use "rlp";
use "libs/crypto/ecies";
use "libs/random/hmac_drbg_random";
use "libs/crypto/encryption/aes/ctr_aes128";

local
  structure Random = HmacDrbgRandom
  structure Hash = Sha256
  structure Secp256k1 = Secp256k1
  structure Encryptor = CtrAes128
  structure Ecies = Ecies(
    structure Encryptor = Encryptor
    structure Hash = Hash
    structure Random = Random
  )
in
  structure Handshake =
  struct

    exception Handshake of string

    datatype authMsgV4 = AuthMsgV4 of
         Word8Vector.vector * Word8Vector.vector *
         Word8Vector.vector * Word32.word

    val authBodyLen  = 65 (* signature *) + 64 (* pubkey *) + 32 (* nonce *) +
      4 (* version as word32 *) + 4 (* RLP overhead *)
    val eciesOverhead = 65 (* pubkey *) + 16 (* IV *) + 32 (* MAC *)

    local
      structure Sha256HmacDrbg = HmacDrbg(Hmac(Sha256))
    in
      fun sign_rfc6979 privkey msg =
      let
        val nonceLen = 32

        val drbg = Sha256HmacDrbg.instantiate (privkey, msg, Utils.emptyWord8Vector)
        fun getNonce drbg =
        let
          val zeroNonce = Word8Array.vector (Word8Array.array(nonceLen, 0w0))
          val nonce = Sha256HmacDrbg.generate (drbg, nonceLen, Utils.emptyWord8Vector)
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

    fun makeAuthMsg (staticKeyPair, remotePublicKey) =
    let
      val nonce = Random.generateVector(32, false)
      val ephemeralKeyPair = KeyPair.random()

      (* val nonce = Word8Vector.fromList [
        0wxbf, 0wxc2, 0wx5b, 0wx39, 0wx27, 0wx58, 0wxfb, 0wx0a,
        0wx01, 0wx1f, 0wxf6, 0wx47, 0wx0c, 0wxc3, 0wx92, 0wxc3,
        0wxf4, 0wx3d, 0wxc6, 0wx0e, 0wx19, 0wxd6, 0wxfd, 0wxac,
        0wx24, 0wx10, 0wxd3, 0wx3d, 0wx61, 0wxad, 0wx73, 0wx0f
      ]

      val ephemeralKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wxfa, 0wx5d, 0wx82, 0wx36, 0wx7d, 0wxed, 0wx4b, 0wx25,
          0wxd7, 0wxa1, 0wx2e, 0wxd6, 0wx6a, 0wx33, 0wx3b, 0wx98,
          0wxb1, 0wx94, 0wxe2, 0wx80, 0wx70, 0wx16, 0wxa1, 0wx2c,
          0wxd1, 0wx57, 0wxf4, 0wx0b, 0wxb5, 0wxb8, 0wx96, 0wx6d
        ]
      ) *)

      val staticSharedSecret = Ecies.computeSharedSecret (
        KeyPair.getPrivateKey staticKeyPair, remotePublicKey
      )

      val toSign = Utils.word8VectorXorb (staticSharedSecret, nonce)

      val sign = sign_rfc6979 (KeyPair.getPrivateKey ephemeralKeyPair) toSign
      val r = #r sign
      val s = #s sign
      val recid = Word8Vector.fromList [Word8.fromInt (#recid sign)]
       (* concatenate the signature to be sent *)
      val formattedSignature = Word8Vector.concat [r, s, recid]

       (* remove the first byte as it should not be sent *)
      val formattedInitiatorPublicKey = Utils.takeVectorSlice (
        KeyPair.getPublicKey staticKeyPair, 1, NONE
      )

      val msgVersion = 0w4
    in
      AuthMsgV4 (formattedSignature, formattedInitiatorPublicKey, nonce, msgVersion)
    end

    fun sealEIP8(authMsg, receiverPublicKey) =
    let
      fun encodeAuthMsg (AuthMsgV4(sign, pubkey, nonce, version)) =
      let
        val rlpEncodedSign = Rlp.Encoder.encodeWord8Vector sign
        val rlpEncodedPubkey = Rlp.Encoder.encodeWord8Vector pubkey
        val rlpEncodedNonce = Rlp.Encoder.encodeWord8Vector nonce
        val rlpEncodedVersion = Rlp.Encoder.encodeWord32 version
      in
        Rlp.getRlpResultData (
          Rlp.Encoder.encodeRlpResultsList [
            rlpEncodedSign, rlpEncodedPubkey, rlpEncodedNonce, rlpEncodedVersion
          ]
        )
      end
      val encodedAuthMsg = encodeAuthMsg authMsg

      (* Pad with random amount of data. the amount needs to be at least 100 bytes to make
       *  the message distinguishable from pre-EIP-8 handshakes.
       * Adding a random amount in range [100, 300] is recommended.*)
      val padLen = 100 + Word8.toInt (
        Random.generateWord8 false
          mod
        0w201
      )
      val pad = Random.generateVector (padLen, false)

      (* val padLen = 147
      val pad = Word8Array.vector (Word8Array.array(padLen, 0w0)) *)

      val buf = Word8Vector.concat [encodedAuthMsg, pad]

      val prefix = Utils.word16ToWord8Vector (
        Word16.fromInt (Word8Vector.length buf + eciesOverhead)
      )

      val encodedAuthBody = Ecies.encrypt (
        receiverPublicKey,
        buf,
        Utils.emptyWord8Vector,
        prefix
      )
    in
      Word8Vector.concat [prefix, encodedAuthBody]
    end

    fun initiatorEncHandshake ( (* staticKeyPair : KeyPair.keyPair, remotePublicKey *) ) =
    let
      val staticKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wx27, 0wx70, 0wx46, 0wxd0, 0wx1e, 0wx40, 0wx87, 0wxc3,
          0wx67, 0wxcc, 0wx3b, 0wx6d, 0wx84, 0wxe4, 0wx73, 0wxe1,
          0wx2f, 0wxbe, 0wx08, 0wx91, 0wx97, 0wxc6, 0wx49, 0wxc3,
          0wx4d, 0wxda, 0wxe9, 0wx2d, 0wx9b, 0wx7f, 0wx7f, 0wxe0
        ]
      )

      val remoteKey = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wx04, 0wx1e, 0wx1f, 0wx1f, 0wx99, 0wx81, 0wx24, 0wx2d,
          0wxb7, 0wx71, 0wx56, 0wx64, 0wx31, 0wx3b, 0wxc0, 0wx96,
          0wxca, 0wx9e, 0wx88, 0wxb5, 0wxbe, 0wxb7, 0wxc9, 0wx64,
          0wxb8, 0wxf9, 0wx60, 0wx11, 0wx2d, 0wx4e, 0wx94, 0wxa4
        ]
      )

      val remotePublicKey = KeyPair.getPublicKey remoteKey

      val authMsg = makeAuthMsg (staticKeyPair, remotePublicKey)
      val authPacket = sealEIP8 (authMsg, remotePublicKey)
    in
      {pack=authPacket, msg=authMsg}
    end

    fun parseAuthPacket () = 2

    fun receiverEncHandshake (authPacket (* , staticKeyPair *) ) =
    let
      val staticKeyPair = KeyPair.fromPrivateKey (
        Word8Vector.fromList [
          0wx04, 0wx1e, 0wx1f, 0wx1f, 0wx99, 0wx81, 0wx24, 0wx2d,
          0wxb7, 0wx71, 0wx56, 0wx64, 0wx31, 0wx3b, 0wxc0, 0wx96,
          0wxca, 0wx9e, 0wx88, 0wxb5, 0wxbe, 0wxb7, 0wxc9, 0wx64,
          0wxb8, 0wxf9, 0wx60, 0wx11, 0wx2d, 0wx4e, 0wx94, 0wxa4
        ]
      )

      val plainSize = 307
      val _ = if Word8Vector.length authPacket < plainSize
              then raise Handshake ("Size underflow, need at least 307 bytes")
              else ()

      val prefix = Utils.takeVectorSlice(authPacket, 0, SOME 2)

      val authSize = Word16.toInt (Utils.word8VectorToWord16 (prefix))

      val encryptedAuthBody = Utils.takeVectorSlice (
        authPacket, 2, SOME authSize
      )

      val encodedPaddedAuthBody = Ecies.decrypt(
        KeyPair.getPrivateKey staticKeyPair,
        encryptedAuthBody,
        Utils.emptyWord8Vector,
        prefix
      )

      val encodedAuthBody = Utils.takeVectorSlice(
        encodedPaddedAuthBody, 0, SOME authBodyLen
      )

      fun decodeAuthMsg encodedAuthMsg =
      let
        val rlpEncodedAuthMsg = Rlp.Decoder.formRlpResult encodedAuthMsg
        val decodedList = Rlp.Decoder.decodeList rlpEncodedAuthMsg

        val sign = Rlp.Decoder.decodeWord8Vector (
          List.nth (decodedList, 0)
        )
        val pubkey = Rlp.Decoder.decodeWord8Vector (
          List.nth (decodedList, 1)
        )
        val nonce = Rlp.Decoder.decodeWord8Vector (
          List.nth (decodedList, 2)
        )
        val version = Rlp.Decoder.decodeWord32 (
          List.nth (decodedList, 3)
        )
      in
        AuthMsgV4(sign, pubkey, nonce, version)
      end
    in
      decodeAuthMsg encodedAuthBody
    end

  end
end
