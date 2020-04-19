signature SECP256K1 =
sig
  exception Secp256k1 of string

  val start : unit -> unit
  val stop : unit -> unit

  val ecdsaVerify : Word8Vector.vector ->
    Word8Vector.vector * Word8Vector.vector -> bool

    (* TODO: does not work in current implementation *)
  (* val ecdsaSign : Word8Vector.vector -> Word8Vector.vector ->
    Word8Vector.vector -> Word8Vector.vector *)

  val ecdsaSignCompact : Word8Vector.vector -> Word8Vector.vector -> Word8Vector.vector ->
    {r: Word8VectorSlice.vector, recid: int, s: Word8VectorSlice.vector}

  val ecdsaRecoverCompact : Word8Vector.vector ->
    int * Word8Vector.vector * Word8Vector.vector ->
      bool -> Word8VectorSlice.vector

  val ecdsaPrivkeyVerify : Word8Vector.vector -> bool

  val ecdsaPubkeyVerify: Word8Vector.vector -> bool

  val ecdsaPubkeyCreate: Word8Vector.vector -> bool ->
    Word8VectorSlice.vector

  val ecdsaPubkeyDecompress: Word8Vector.vector -> Word8VectorSlice.vector

end

local
  open Foreign

  val secp256k1_lib = loadLibrary "libs/secp256k1/src/libsecp256k1.so"

  val startCall = buildCall0((getSymbol secp256k1_lib "secp256k1_start"), (), cVoid)
  val stopCall = buildCall0((getSymbol secp256k1_lib "secp256k1_stop"), (), cVoid)

  val ecdsaVerifyCall = buildCall6((getSymbol secp256k1_lib "secp256k1_ecdsa_verify"),
                          (cByteArray, cInt, cByteArray, cInt, cByteArray, cInt),
                          cInt)

  val ecdsaSignCall = buildCall6((getSymbol secp256k1_lib "secp256k1_ecdsa_verify"),
                          (cByteArray, cInt, cArrayPointer cUchar, cStar cInt,
                           cByteArray, cByteArray),
                           cInt)

  val ecdsaSignCompactCall = buildCall6((getSymbol secp256k1_lib "secp256k1_ecdsa_sign_compact"),
                              (cByteArray, cInt, cArrayPointer cUchar,
                              cByteArray, cByteArray, cStar cInt),
                              cInt)

  val ecdsaRecoverCompactCall = buildCall7((getSymbol secp256k1_lib "secp256k1_ecdsa_recover_compact"),
                                  (cByteArray, cInt, cByteArray, cArrayPointer cUchar,
                                  cStar cInt, cInt, cInt),
                                  cInt)

  val ecdsaPrivkeyVerifyCall = buildCall1((getSymbol secp256k1_lib "secp256k1_ecdsa_seckey_verify"),
                                  (cByteArray), cInt)

  val ecdsaPubkeyVerifyCall = buildCall2((getSymbol secp256k1_lib "secp256k1_ecdsa_pubkey_verify"),
                                (cByteArray, cInt), cInt)

  val ecdsaPubkeyCreateCall = buildCall4((getSymbol secp256k1_lib "secp256k1_ecdsa_pubkey_create"),
                                (cArrayPointer cUchar, cStar cInt, cByteArray, cInt),
                                cInt)

  val ecdsaPubkeyDecompressCall = buildCall2((getSymbol secp256k1_lib "secp256k1_ecdsa_pubkey_decompress"),
                                    (cArrayPointer cUchar, cStar cInt), cInt)
in
  structure Secp256k1 : SECP256K1 =
  struct
     (* indicates foreign function has not returned successful return code *)
    exception Secp256k1 of string

     (* internal function used to create an output buffer for foreign call *)
    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    fun ensureBufferSize (v, size, buf_name) =
      if
        Word8Vector.length v <> size
      then
        raise Fail ("The size of the " ^ buf_name ^ " is incorrect")
      else ()

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

    val started = ref false

    fun ensureStarted () =
      if
        not (!started)
      then
        raise Fail "The library has not been started"
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

    fun ecdsaVerify pubkey (msg, sign)  =
    let
      val _ = ensureStarted ()
      val len = Word8Vector.length
      val status = ecdsaVerifyCall (msg, len msg, sign, len sign, pubkey, len pubkey)
    in
      if
        status = ~2
      then raise Secp256k1 "Invalid signature"
      else if
        status = ~1
      then raise Secp256k1 "Invalid public key"
      else status = 1
    end

    fun ecdsaSign privkey msg nonce =
    let
      val _ = ensureStarted ()
      val _ = ensureBufferSize (privkey, 32, "private key")
      val _ = ensureBufferSize (nonce, 32, "nonce")

      val len = Word8Vector.length

      val sign = createBuffer (72)
      val sign_len = ref 0
      val status = ecdsaSignCall (msg, len msg, sign, sign_len, privkey, nonce)
    in
      if
        status = 1
      then
        arrayToWord8Vector sign
      else
        raise Secp256k1 "Invalid nonce. Try another one"
    end

    fun ecdsaSignCompact privkey msg nonce =
    let
      val _ = ensureStarted ()
      val _ = ensureBufferSize (privkey, 32, "private key")
      val _ = ensureBufferSize (nonce, 32, "nonce")

      val len = Word8Vector.length

      val sign = createBuffer (64)
      val recid = ref 0
      val status = ecdsaSignCompactCall (msg, len msg, sign, privkey, nonce, recid)
      val sign_vec = arrayToWord8Vector sign
      val r = Word8VectorSlice.vector (Word8VectorSlice.slice (sign_vec, 0, SOME 32))
      val s = Word8VectorSlice.vector (Word8VectorSlice.slice (sign_vec, 32, SOME 32))
    in
      if
        status = 1
      then
        {recid = (!recid), r = r, s = s}
      else
        raise Secp256k1 "Invalid nonce. Try another one"
    end

    fun ecdsaRecoverCompact msg (recid, r, s) compressed =
    let
      val _ = ensureStarted()
      val _ = ensureBufferSize (r, 32, "r component")
      val _ = ensureBufferSize (s, 32, "s component")

      val sign = Word8Vector.concat [r, s]

      val len = Word8Vector.length

      val compressed_val = if compressed then 1 else 0
      val pubkey = if compressed
        then createBuffer (33)
        else createBuffer (65)
      val pubkey_len = ref 0

      val status = ecdsaRecoverCompactCall(msg, len msg, sign, pubkey, pubkey_len, compressed_val, recid)
    in
      if
        status = 1
      then
        Word8VectorSlice.vector (
          Word8VectorSlice.slice (arrayToWord8Vector pubkey, 0, SOME (!pubkey_len))
        )
      else
        raise Secp256k1 "Signature is not valid"
    end

    fun ecdsaPrivkeyVerify privkey =
    let
      val _ = ensureStarted ()
      val _ = ensureBufferSize (privkey, 32, "private key")

      val status = ecdsaPrivkeyVerifyCall privkey
    in
      status = 1
    end

    fun ecdsaPubkeyVerify pubkey =
    let
      val _ = ensureStarted ()

      val status = ecdsaPubkeyVerifyCall(pubkey, Word8Vector.length pubkey)
    in
      status = 1
    end

    fun ecdsaPubkeyCreate privkey (compressed : bool) =
    let
      val _ = ensureStarted ()
      val _ = ensureBufferSize (privkey, 32, "private key")

      val compressed_val = if compressed then 1 else 0
      val pubkey = if compressed
        then createBuffer (33)
        else createBuffer (65)
      val pubkey_len = ref 0

      val status = ecdsaPubkeyCreateCall(pubkey, pubkey_len, privkey, compressed_val)
    in
      if
        status = 1
      then
        Word8VectorSlice.vector (
          Word8VectorSlice.slice (arrayToWord8Vector pubkey, 0, SOME (!pubkey_len))
        )
      else
        raise Secp256k1 "Private key is invalid"
    end

    fun ecdsaPubkeyDecompress pubkey =
    let
      val _ = ensureStarted ()

      val pubkey_pad = Word8Vector.concat [
        pubkey, Word8Array.vector (Word8Array.array(65 - (Word8Vector.length pubkey), 0w0))
      ]
      val pubkey_buf = word8VectorToArray pubkey_pad
      val pubkey_len = ref (Word8Vector.length pubkey)
      val status = ecdsaPubkeyDecompressCall(pubkey_buf, pubkey_len)
    in
      if status = 1
      then
        Word8VectorSlice.vector (
          Word8VectorSlice.slice (arrayToWord8Vector pubkey_buf, 0, SOME (!pubkey_len))
        )
      else raise Secp256k1 "Public key is invalid"
    end

  end
end
