use "libs/crypto/drbg/drbgSig";
use "libs/crypto/drbg/internalDrbgSig";
use "libs/random/random";

functor Drbg (InternalDrbg : INTERNAL_DRBG) :> DRBG =
struct
  exception DrbgFail of string
  exception DrbgCatastrophicFail

  type state = InternalDrbg.state

  val reseedCounter = ref 0

  fun getWord8VectorFromOption opt =
    case opt of
         SOME (vec) => vec
       | NONE => Word8Vector.fromList []

  fun instantiate (ps) =
  let
    val psVec = getWord8VectorFromOption ps
    val _ = (* validate personalization string *)
      if Word8Vector.length psVec > InternalDrbg.maxPersonalizationStringLength
      then raise DrbgFail "Pesonalozation string is too long"
      else ()

    val entropyAndNonce = Random.useed 48
    val emptyVec = Word8Vector.fromList []
  in
    (case entropyAndNonce of
          SOME (vec) => (
            reseedCounter := 0;
            InternalDrbg.instantiate(vec, emptyVec, psVec)
          )
        | NONE => raise DrbgCatastrophicFail)
  end

  fun reseed (state, addInput) =
  let
    val addInputVec = getWord8VectorFromOption addInput
    val _ = (* validate additional input *)
      if Word8Vector.length addInputVec > InternalDrbg.maxAdditionalInputLength
      then raise DrbgFail "Addigional input is too long"
      else ()

    val entropy = Random.useed 32
  in
    (case entropy of
          SOME (vec) => (
            reseedCounter := 0;
            InternalDrbg.reseed (state, vec, addInputVec)
          )
        | NONE => raise DrbgCatastrophicFail)
  end

  fun generate (state, outLen, predictionResistance, addInput) =
  let
    val addInputVec = getWord8VectorFromOption addInput
    val _ = (* validate additional input *)
      if Word8Vector.length addInputVec > InternalDrbg.maxAdditionalInputLength
      then raise DrbgFail "Addigional input is too long"
      else ()

    val _ = (* validate requested length *)
      if outLen > InternalDrbg.maxNumberOfBitsPerRequest
      then raise DrbgFail "Random string requested is too long"
      else ()

    fun internalGenerate (state, outLen, addInpVec) =
      (reseedCounter := (!reseedCounter) + 1;
       InternalDrbg.generate (state, outLen, addInpVec))
  in
    if
      predictionResistance
        orelse
      (!reseedCounter) = InternalDrbg.maxNumberOfRequestsBetweenReseeds
    then
      (reseed (state, addInput);
       internalGenerate (state, outLen, Word8Vector.fromList []))
    else
      internalGenerate (state, outLen, addInputVec)
  end

end
