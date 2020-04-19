use "libs/PackWord";

structure Utils =
  struct
    local
      fun log256 t = Math.ln(t) / Math.ln(256.0)
    in
      fun getUIntSize (a : int) =
        if a >= 0
          then Real.ceil(log256 (Real.fromInt (a+1)))
        else raise Domain
    end

    fun isWord8VectorEmpty vec =
      Word8Vector.length vec = 0

    fun takeVectorSlice (vec, offset, len) =
      Word8VectorSlice.vector (Word8VectorSlice.slice (vec, offset, len))

    fun printWord8Vector vec =
    let
      val len = Word8Vector.length vec
      fun loop i =
        if i < len
        then
          (print(Word8.toString (Word8Vector.sub (vec, i)) ^ " "); loop (i+1))
        else
          ()
    in
      loop 0
    end


      (* transforms from word8Vector to Word *)
    fun word8VectorToWord8 (word8VectorData) =
      Word8.fromLargeWord (PackWord8Big.subVec (word8VectorData, 0))

    fun word8VectorToWord16 (word8VectorData) =
      Word16.fromLargeWord (PackWord16Big.subVec (word8VectorData, 0))

(*  fun word8VectorToWord24 (word8VectorData) =
      Word32.fromLargeWord (PackWord24Big.subVec (word8VectorData, 0)) *)

    fun word8VectorToWord32 (word8VectorData) =
      Word32.fromLargeWord (PackWord32Big.subVec (word8VectorData, 0))

(*  fun word8VectorToWord40 (word8VectorData) =
      Word32.fromLargeWord (PackWord40Big.subVec (word8VectorData, 0)) *)

(*  fun word8VectorToWord48 (word8VectorData) =
      Word32.fromLargeWord (PackWord48Big.subVec (word8VectorData, 0)) *)

(*  fun word8VectorToWord56 (word8VectorData) =
      Word32.fromLargeWord (PackWord56Big.subVec (word8VectorData, 0)) *)

    fun word8VectorToWord64 (word8VectorData) =
      Word64.fromLargeWord (PackWord64Big.subVec (word8VectorData, 0))


      (* transforms from words to word8Vector *)
(*    fun word8ToWord8Vector (item : Word8.word) =
      let
        val arr = Word8Array.array(PackWord8Big.bytesPerElem, 0w0);
      in
        PackWord8Big.update (arr, 0, Word8.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word16ToWord8Vector (item : Word16.word) =
      let
        val arr = Word8Array.array(PackWord16Big.bytesPerElem, 0w0);
      in
        PackWord16Big.update (arr, 0, Word16.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word24ToWord8Vector (item : Word24.word) =
      let
        val arr = Word8Array.array(PackWord24Big.bytesPerElem, 0w0);
      in
        PackWord24Big.update (arr, 0, Word24.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word32ToWord8Vector (item : Word32.word) =
      let
        val arr = Word8Array.array(PackWord32Big.bytesPerElem, 0w0);
      in
        PackWord32Big.update (arr, 0, Word32.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word40ToWord8Vector (item : Word40.word) =
      let
        val arr = Word8Array.array(PackWord40Big.bytesPerElem, 0w0);
      in
        PackWord40Big.update (arr, 0, Word40.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word48ToWord8Vector (item : Word48.word) =
      let
        val arr = Word8Array.array(PackWord48Big.bytesPerElem, 0w0);
      in
        PackWord48Big.update (arr, 0, Word48.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word56ToWord8Vector (item : Word56.word) =
      let
        val arr = Word8Array.array(PackWord56Big.bytesPerElem, 0w0);
      in
        PackWord56Big.update (arr, 0, Word56.toLargeWord item);
        Word8Array.vector arr
      end;

    fun word64ToWord8Vector (item : Word64.word) =
      let
        val arr = Word8Array.array(PackWord64Big.bytesPerElem, 0w0);
      in
        PackWord64Big.update (arr, 0, Word64.toLargeWord item);
        Word8Array.vector arr
      end; *)

  end;

