signature DRBG =
sig
  exception DrbgFail of string
  exception DrbgCatastrophicFail

  type state

  val instantiate : Word8Vector.vector option -> state

  val reseed : state * Word8Vector.vector option -> unit

  val generate : state * int * bool * Word8Vector.vector option ->
    Word8Vector.vector
end


