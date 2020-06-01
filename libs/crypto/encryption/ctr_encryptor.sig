signature CTR_ENCRYPTOR =
sig
  exception Encryptor of string
  type encryptor

	val blockSize : int
	val keySize : int

  val createEncryptor : unit -> encryptor

  val destroyEncryptor : encryptor -> unit

  val initEncryptor : encryptor *
    Word8Vector.vector * Word8Vector.vector -> unit

  val setEncryptorIV : encryptor * Word8Vector.vector -> unit

  val encrypt : encryptor * Word8Vector.vector -> Word8Vector.vector
end
