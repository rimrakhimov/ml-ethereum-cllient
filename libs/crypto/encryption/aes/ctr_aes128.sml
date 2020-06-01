use "libs/crypto/encryption/ctr_encryptor.sig";

local
  open Foreign

  val aes_lib = loadLibrary "libs/crypto/encryption/aes/src/aes_ml.so"

  val createEncryptorCall = buildCall0((getSymbol aes_lib "create_ctx"), (), cPointer)

  val destroyEncryptorCall = buildCall1((getSymbol aes_lib "destroy_ctx"), (cPointer), cVoid)

  val initEncryptorCall = buildCall3((getSymbol aes_lib "AES_init_ctx_iv"),
                              (cPointer, cByteArray, cByteArray), cVoid)

  val setEncryptorIVCall = buildCall2((getSymbol aes_lib "AES_ctx_set_iv"),
                            (cPointer, cByteArray), cVoid)

  val ctrEncryptCall = buildCall3((getSymbol aes_lib "AES_CTR_xcrypt_buffer"),
                        (cPointer, cArrayPointer cUchar, cUint32), cVoid)
in
  structure CtrAes128 :> CTR_ENCRYPTOR =
    struct
      exception Encryptor of string

      type encryptor = Foreign.Memory.voidStar

      local
        fun toList a = Array.foldr op:: [] a
      in
        fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
      end

      local
        fun toList v = Word8Vector.foldr op :: [] v
      in
        fun word8VectorToArray v = Array.fromList (toList v)
      end

      val blockSize = 16
      val keySize = 16

      fun createEncryptor() = createEncryptorCall()

      fun destroyEncryptor(encryptor) = destroyEncryptorCall(encryptor)

      fun initEncryptor(encryptor, key, iv) = initEncryptorCall(encryptor, key, iv)

      fun setEncryptorIV(encryptor, iv) = setEncryptorIVCall(encryptor, iv)

      fun encrypt(encryptor, data) =
      let
        val buf = word8VectorToArray data
        val _ = ctrEncryptCall(encryptor, buf, Word8Vector.length data)
      in
        arrayToWord8Vector buf
      end

    end
end
