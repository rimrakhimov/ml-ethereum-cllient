use "libs/crypto/drbg/internalDrbgSig";

signature DRBG =
sig
  exception Drbg of string

  type state

  val instantiate : Word8Vector.vector * Word8Vector.vector *
    Word8Vector.vector * int -> state

  val reseed : state *
end
