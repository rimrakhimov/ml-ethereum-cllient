use "libs/crypto/encryption/ctr_encryptor.sig";
use "libs/crypto/hash/hashSig.sml";
use "libs/secp256k1/secp256k1.sml";
use "keyPair.sml";
use "utils.sml";
use "libs/crypto/kdf/concatKDF";
use "libs/random/random.sig";
use "libs/crypto/hmac";

signature ECIES =
sig
  val computeSharedSecret : Word8Vector.vector * Word8Vector.vector ->
    Word8Vector.vector
end

functor Ecies (
  structure Encryptor : CTR_ENCRYPTOR
  structure Hash : HASH
  structure Random : RANDOM
) =
struct
  exception Ecies of string

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
    (* TODO: does not verify length of secret key and mac key *)
    fun deriveKeyMaterials (ephemeralPrivkey, remotePubkey, skLen, macLen, s1) =
    let
      val sharedSecret = computeSharedSecret (ephemeralPrivkey, remotePubkey)
      val keyMaterial = Kdf.kdf (sharedSecret, skLen + macLen, s1)

      val encKey = Utils.takeVectorSlice (keyMaterial, 0, SOME skLen)
      val macKey = Utils.takeVectorSlice (keyMaterial, skLen, SOME macLen)
    in
      {encKey = encKey, macKey = macKey}
    end
  end

  fun symEncrypt (key, msg) =
  let
    val iv = Random.generateVector (Encryptor.blockSize, false)
    (* val iv = Word8Vector.fromList [
      0wx99, 0wxa7, 0wxbe, 0wxb0, 0wx0b, 0wxa5, 0wx72, 0wx40,
      0wxe4, 0wxc0, 0wx37, 0wx19, 0wxcb, 0wx35, 0wx46, 0wx7a
    ] *)

    val ctr = Encryptor.createEncryptor()
    val _ = Encryptor.initEncryptor(ctr, key, iv)

    val encryptedMsg = Encryptor.encrypt(ctr, msg)

    val _ = Encryptor.destroyEncryptor (ctr)
  in
    Word8Vector.concat [iv, encryptedMsg]
  end

  fun symDecrypt (key, iv, encMsg) =
  let
    val ctr = Encryptor.createEncryptor()
    val _ = Encryptor.initEncryptor (ctr, key, iv)

    val decryptedMsg = Encryptor.encrypt(ctr, encMsg)
  in
    decryptedMsg
  end


  local
    structure Hmac = Hmac(Hash)
  in
    fun messageTag (key, msg, shared) =
    let
      val dataToTag = Word8Vector.concat [msg, shared]
      val tag = Hmac.hmac key dataToTag
    in
      tag
    end
  end

   (* Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1.
    *
    * s1 and s2 contain shared information that is not part of the resulting
    * ciphertext. s1 is fed into key derivation, s2 is fed into the MAC. If the
    * shared information parameters aren't being used, they should be empty vectors. *)
  fun encrypt (pubkey, msg, s1, s2) =
  let
    val R = KeyPair.random ()
    (* val R = KeyPair.fromPrivateKey (
      Word8Vector.fromList [
        0wxb6, 0wxb6, 0wx52, 0wx93, 0wxe5, 0wx12, 0wxf4, 0wxb0,
        0wxf9, 0wx62, 0wx21, 0wx2f, 0wx73, 0wx4a, 0wx1c, 0wx26,
        0wx4e, 0wxc4, 0wx45, 0wxe2, 0wx61, 0wxe0, 0wx90, 0wx1d,
        0wxd2, 0wx92, 0wx9b, 0wxa6, 0wx23, 0wx73, 0wx02, 0wxb8
      ]
    ) *)

    val keyMaterial = deriveKeyMaterials (
      KeyPair.getPrivateKey R, pubkey, 16, 16, s1
    )
    val encKey = #encKey keyMaterial
    val macKey = #macKey keyMaterial

    val ivAndEncryptedMsg = symEncrypt (encKey, msg)

    val tag = messageTag (Hash.hash(macKey), ivAndEncryptedMsg, s2)
  in
    Word8Vector.concat [KeyPair.getPublicKey R, ivAndEncryptedMsg, tag]
  end

  fun validateMessageTag (msg, macKey, s2, providedMsgTag) =
  let
    val realMsgTag = messageTag (Hash.hash(macKey), msg, s2)
  in
    if realMsgTag <> providedMsgTag
    then raise Ecies ("Message has non-valid MAC tag")
    else ()
  end

   (* Decrypt decrypts an ECIES ciphertext. *)
  fun decrypt (privkey, encMsg, s1, s2) =
  let
     (* TODO: add validity checkings *)
    val RPubkey = Utils.takeVectorSlice (encMsg, 0, SOME 65)
    val keyMaterial = deriveKeyMaterials (
      privkey, RPubkey, 16, 16, s1
    )
    val encKey = #encKey keyMaterial
    val macKey = #macKey keyMaterial

    val mStart = 65
    val mLen = Word8Vector.length encMsg - mStart - Hash.outputSize

    val ivAndEncryptedMsg = Utils.takeVectorSlice (encMsg, mStart, SOME mLen)

    val messageTag = Utils.takeVectorSlice (encMsg, mStart + mLen, NONE)
    val _ = validateMessageTag (ivAndEncryptedMsg, macKey, s2, messageTag)

    val iv = Utils.takeVectorSlice (ivAndEncryptedMsg, 0, SOME 16)
    val encryptedMsg = Utils.takeVectorSlice (ivAndEncryptedMsg, 16, NONE)
  in
    symDecrypt(encKey, iv, encryptedMsg)
  end


end

