use "libs/crypto/hmac";

signature INTERNAL_DRBG =
sig
  type state

  val maxEntropyLength : int
  val maxPersonalizationStringLength : int
  val maxAdditionalInputLength : int
  val maxNumberOfBitsPerRequest : int
  val maxNumberOfRequestsBetweenReseeds : int

  val instantiate : Word8Vector.vector * Word8Vector.vector *
    Word8Vector.vector -> state

  val reseed : state * Word8Vector.vector *
    Word8Vector.vector -> unit

  val generate : state * int * Word8Vector.vector -> Word8Vector.vector
end
