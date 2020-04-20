use "libs/crypto/drbg/internalDrbgSig";
use "libs/crypto/hmac";

functor HmacDrbg (Hmac : HMAC) : INTERNAL_DRBG =
struct
  datatype state = State of Word8Vector.vector ref * Word8Vector.vector ref

  val maxEntropyLength = 34359738368                        (* 2^35 *)
  val maxPersonalizationStringLength = 34359738368          (* 2^35 *)
  val maxAdditionalInputLength = 34359738368                (* 2^35 *)
  val maxNumberOfBitsPerRequest = 524288                    (* 2^19 *)
  val maxNumberOfRequestsBetweenReseeds = 281474976710656   (* 2^48 *)

  (* Internal function used to update the internal state of DRNG.
   *  Corresponds to HMAC_DRBG_Update in NIST specification *)
  fun update(State(K, V), data) =
  let
    fun update_K_V (K, V, padByte) = (
      K := Hmac.hmac (!K) (Word8Vector.concat [!V, Word8Vector.fromList[padByte], data]);
      V := Hmac.hmac (!K) (!V)
    )
  in
    update_K_V (K, V, 0wx00);
    if Word8Vector.length data > 0
    then update_K_V (K, V, 0wx01)
    else ()
  end


  fun instantiate (entropy, nonce, ps) =
  let
    val seed = Word8Vector.concat [entropy, nonce, ps]
    val K = ref (Word8Array.vector(
      Word8Array.array(Hmac.Hash.outputSize, 0w0)
    ))
    val V = ref (Word8Array.vector(
      Word8Array.array(Hmac.Hash.outputSize, 0w1)
    ))
    val state = State(K, V)
  in
    update(state, seed);
    state
  end

  fun reseed (state, entropy, additionalInput) =
  let
    val seed = Word8Vector.concat [entropy, additionalInput]
  in
    update (state, seed)
  end

  fun generate (state, outLen, additionalInput) =
  let
    val len = Word8Vector.length
    val _ = if len additionalInput > 0
            then update(state, additionalInput)
            else ()
    val State(ref key, V) = state
    val h = Hmac.hmac key
    fun loop (res) =
      if
        len res < outLen
      then
          (V := h (!V); loop (Word8Vector.concat [res, (!V)]))
      else
        Word8VectorSlice.vector (Word8VectorSlice.slice (res, 0, SOME outLen))

    val res = loop (Word8Vector.fromList [])
  in
    update(state, additionalInput);
    res
  end

end
