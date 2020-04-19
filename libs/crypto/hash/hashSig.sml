signature HASH =
sig
  val outputSize : int
  val blockSize : int
  val hash : Word8Vector.vector -> Word8Vector.vector
end
