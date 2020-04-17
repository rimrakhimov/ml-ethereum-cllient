local
  open Foreign

  val secp256k1_lib = loadLibrary "libs/secp256k1/src/libsecp256k1.so"

  val startCall = buildCall0((getSymbol secp256k1_lib "secp256k1_start"), (), cVoid)
  val stopCall = buildCall0((getSymbol secp256k1_lib "secp256k1_stop"), (), cVoid)

  val ecdsaVerifyCall = buildCall6((getSymbol secp256k1_lib "secp256k1_ecdsa_verify"),
                          (cByteArray, cInt, cByteArray, cInt, cByteArray, cInt),
                          cInt)

  val ecdsaPubkeyCreateCall = buildCall4((getSymbol secp256k1_lib "secp256k1_ecdsa_pubkey_create"),
                                (cArrayPointer cUchar, cStar cInt, cByteArray, cInt),
                                cInt)
in
  structure Secp256k1 =
  struct
    exception Secp256k1 of string

     (* internal function used to create an output buffer for foreign call *)
    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    local
      fun toList a = Array.foldr op:: [] a
    in
      fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
    end

    val started = ref false

    fun ensureStarted () =
      if
        not (!started)
      then
        raise Secp256k1 "The library has not been started"
      else ()

    fun start () =
    let
      val _ = startCall()
    in
      started := true
    end

    fun stop () =
    let
      val _ = stopCall()
    in
      started := false
    end

    fun ecdsaPubkeyCreate privkey (compressed : bool) =
    let
      val _ = ensureStarted ()


      val pubkey = createBuffer 65
      val pubkey_len = ref 0
      val status = ecdsaPubkeyCreateCall(pubkey, pubkey_len, privkey, 0)
    in
      if
        ecdsaPubkeyCreateCall(pubkey, pubkey_len, privkey, 0) = 1
      then
       arrayToWord8Vector pubkey
      else
        raise Secp256k1 "Private key was invalid"

    end
  end
end
