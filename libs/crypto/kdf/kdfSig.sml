signature KDF =
sig
  exception Kdf of string

  val hash : string
  val hashlen : int

  val kdf : Word8Vector.vector * int * Word8Vector.vector ->
    Word8Vector.vector
end
