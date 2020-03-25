local
  open Foreign

  val aes_lib = loadLibrary "libs/aes/aes_ml.so"

  val createEncryptorCall = buildCall0((getSymbol aes_lib "create_ctx"), (), cPointer)

  val destroyEncryptorCall = buildCall1((getSymbol aes_lib "destroy_ctx"), (cPointer), cVoid)

  val initEncryptorCall = buildCall3((getSymbol aes_lib "AES_init_ctx_iv"),
                              (cPointer, cByteArray, cByteArray), cVoid)

  val setEncryptorIVCall = buildCall2((getSymbol aes_lib "AES_ctx_set_iv"),
                            (cPointer, cByteArray), cVoid)

  val ctrEncryptCall = buildCall3((getSymbol aes_lib "AES_CTR_xcrypt_buffer"),
                        (cPointer, cByteArray, cUint32), cVoid)

  val printDataCall = buildCall2((getSymbol aes_lib "print_data"),
                                 (cByteArray, cInt), cVoid)
in
  structure Aes =
    struct
      fun createEncryptor() = createEncryptorCall()

      fun destroyEncryptor(encryptor) = destroyEncryptorCall(encryptor)

      fun initEncryptor(encryptor, key, iv) = initEncryptorCall(encryptor, key, iv)

      fun setEncryptorIV(encryptor, iv) = setEncryptorIVCall(encryptor, iv)

      fun ctrEncrypt(encryptor, data) =
        ctrEncryptCall(encryptor, data, Word8Vector.length data)

      fun printData(data, len) = printDataCall(data, len)
    end
end
