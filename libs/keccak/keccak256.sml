local
  open Foreign

  val keccak_lib = loadLibrary "libs/keccak/BRCrypto.so"

  val keccak256Call = buildCall3((getSymbol keccak_lib "BRKeccak256"),
                                 (cArrayPointer cUint8, cByteArray, cUint),
                                 cVoid)
in
  structure Keccak256 =
    struct
      local
        val intToWord8 = Word8.fromLargeInt o Int.toLarge
      in
        (* calculates keccak256(data) and returns
            the result as Word8Vector *)
        fun hash (data) =
          let
            val buf = IntArray.array (32, 0)
          in
             keccak256Call(buf, data, Word8Vector.length data);
             Vector.map intToWord8 (Array.vector buf)
          end
      end
    end
end
