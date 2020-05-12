signature RANDOM =
sig
	val generateVector : int * bool -> Word8Vector.vector
	val generateWord8 : bool -> Word8.word
	val generateWord16 : bool -> Word16.word
	val generateWord32 : bool -> Word32.word
	val generateWord64 : bool -> Word64.word
end
