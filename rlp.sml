use "utils";
use "libs/PackWord";

signature RLP =
sig
  type rlpResult

  val getRlpResultData : rlpResult -> Word8Vector.vector
  val getRlpResultOffset : rlpResult -> Word8.word
  val getRlpResultLength : rlpResult -> Word64.word
  val getRlpResultIsList : rlpResult -> bool

  structure Encoder:
  sig
    val encodeRlpResultsList : rlpResult list -> rlpResult

    val encodeWord8Vector : Word8Vector.vector -> rlpResult
    val encodeString : string -> rlpResult

    val encodeWord8 : Word8.word -> rlpResult
    val encodeWord16 : Word16.word -> rlpResult
    val encodeWord32 : Word32.word -> rlpResult
    val encodeWord64 : Word64.word -> rlpResult
  end

  structure Decoder:
  sig
    exception RlpFormat of string

    val formRlpResult : Word8Vector.vector -> rlpResult

    val decodeList : rlpResult -> rlpResult list

    val decodeWord8Vector : rlpResult -> Word8Vector.vector
    val decodeString : rlpResult -> string

    val decodeWord8 : rlpResult -> Word8.word
    val decodeWord16 : rlpResult -> Word16.word
    val decodeWord32 : rlpResult -> Word32.word
    val decodeWord64 : rlpResult -> Word64.word
  end
end

structure Rlp : RLP =
struct
    (* Rlp encoded vector, offset of data beginning, len of data *)
  datatype rlpResult = RlpResult of {data : Word8Vector.vector,
                                       offset : Word8.word,
                                       len : Word64.word,
                                       isList : bool};

  fun getRlpResultData (RlpResult(result)) = #data result
  fun getRlpResultOffset (RlpResult(result)) = #offset result
  fun getRlpResultLength (RlpResult(result)) = #len result
  fun getRlpResultIsList (RlpResult(result)) = #isList result


  structure Encoder =
  struct
    datatype rlpItem = RlpString of Word8Vector.vector |
                       RlpList of rlpItem list;
    local
      fun getPackerUpdater size =
        case size of
             1 => PackWord8Big.update  |
             2 => PackWord16Big.update |
             3 => PackWord24Big.update |
             4 => PackWord32Big.update |
             5 => PackWord40Big.update |
             6 => PackWord48Big.update |
             7 => PackWord56Big.update |
             8 => PackWord64Big.update |
              (* is not raised now, as the maximum
                  Word8Vector length is limited by 8 bytes *)
             _ => raise Overflow
      in
        fun encodeHeader (len : int, isList : bool) =
        let
          val base = if isList then 0xc0 else 0x80
        in
          if
            len < 56
          then
            Word8Vector.fromList [Word8.fromInt (base + len)]
          else
            let
              val lenSize = Utils.getUIntSize(len)
              val prefix = Word8Vector.fromList [Word8.fromInt(base + 55 + lenSize)]
              val packerUpdater = getPackerUpdater lenSize
              val arr = Word8Array.array (lenSize, 0w0)
              val fromIntToLargeWord = Word64.toLarge o Word64.fromInt
            in
              packerUpdater (arr, 0, fromIntToLargeWord len);
              Word8Vector.concat [prefix, Word8Array.vector arr]
            end
        end
      end

      fun encodeRlpString (RlpString(b)) =
      let
        val len = Word8Vector.length b
      in
        if
          len = 1 andalso Word8Vector.sub(b, 0) < 0wx80
        then
          RlpResult({
            data = Word8Vector.fromList [Word8Vector.sub(b, 0)],
            offset = 0w0,
            len = Word64.fromInt len,
            isList = false
          })
        else
          let
            val header = encodeHeader (len, false)
          in
            RlpResult({
              data = Word8Vector.concat [header, b],
              offset = Word8.fromInt (Word8Vector.length header),
              len = Word64.fromInt len,
              isList = false
            })
          end
      end

       (* none of the items are assumed to be encoded prior *)
      fun encodeRlpList (RlpList(l)) =
      let
         (* returns vector instead of rlpResult
          *  as vector is used by encodeRlpList function *)
        fun encodeRlpListItems ([], currentResultVec) =
              currentResultVec
          | encodeRlpListItems ((item : rlpItem) :: ls, currentResultVec) =
            let
              val encodedItem = case item of
                                  RlpString (_) => encodeRlpString item
                                | RlpList (_) => encodeRlpList item
              val encodedItemData = getRlpResultData encodedItem
              val newResultVec = Word8Vector.concat [currentResultVec, encodedItemData]
            in
              encodeRlpListItems (ls, newResultVec)
            end

        val encodedItemsVec = encodeRlpListItems (l, Word8Vector.fromList [])
        val len = Word8Vector.length encodedItemsVec
        val header = encodeHeader (len, true)
      in
        RlpResult({
          data = Word8Vector.concat [header, encodedItemsVec],
          offset = Word8.fromInt (Word8Vector.length header),
          len = Word64.fromInt len,
          isList = true
        })
      end

       (* the whole content of the list is assumed to be rlp encoded *)
      fun encodeRlpResultsList (l : rlpResult list) =
      let
        fun concatenateItems ([], currentResult) =
              currentResult
          | concatenateItems (item :: ls, currentResult) =
            let
              val itemData = getRlpResultData(item)
            in
              concatenateItems (ls, Word8Vector.concat [currentResult, itemData])
            end

        val allItems = concatenateItems(l, Word8Vector.fromList [])
        val len = Word8Vector.length allItems
        val header = encodeHeader (len, true)
      in
        RlpResult({
          data = Word8Vector.concat [header, allItems],
          offset = Word8.fromInt (Word8Vector.length header),
          len = Word64.fromInt len,
          isList = true
        })
      end

      fun encodeString s =
        encodeRlpString (RlpString (Byte.stringToBytes s))

      fun encodeWord8Vector v =
        encodeRlpString (RlpString (v))

      local
        fun normalizeWord (w : Word8Vector.vector) =
        let
          val wordLen = Word8Vector.length w

          fun getNonZeroIndex (currentIndex) =
            if
              currentIndex < wordLen
            then
              if
                Word8Vector.sub (w, currentIndex) <> 0wx0
              then
                currentIndex
              else
                getNonZeroIndex (currentIndex + 1)
            else
              currentIndex + 1    (* all elements are zeros *)

          val nonZeroIndex = getNonZeroIndex 0
        in
          if
            nonZeroIndex < wordLen
          then
            Utils.takeVectorSlice (w, nonZeroIndex, NONE)
          else    (* all elements are zeros *)
            Word8Vector.fromList [0wx0]
        end
      in
        fun encodeWord (w : Word8Vector.vector) =
          encodeRlpString (RlpString (normalizeWord w))
      end


      fun encodeWord8 w =
      let
        val arr = Word8Array.array (PackWord8Big.bytesPerElem, 0w0)
      in
        PackWord8Big.update (arr, 0, Word8.toLarge w);
        encodeWord (Word8Array.vector arr)
      end

      fun encodeWord16 w =
      let
        val arr = Word8Array.array (PackWord16Big.bytesPerElem, 0w0)
      in
        PackWord16Big.update (arr, 0, Word16.toLarge w);
        encodeWord (Word8Array.vector arr)
      end

      fun encodeWord32 w =
      let
        val arr = Word8Array.array (PackWord32Big.bytesPerElem, 0w0)
      in
        PackWord32Big.update (arr, 0, Word32.toLarge w);
        encodeWord (Word8Array.vector arr)
      end

      fun encodeWord64 w =
      let
        val arr = Word8Array.array (PackWord64Big.bytesPerElem, 0w0)
      in
        PackWord64Big.update (arr, 0, Word64.toLarge w);
        encodeWord (Word8Array.vector arr)
      end
  end

  structure Decoder =
  struct
    exception RlpFormat of string;

    local
      fun getPackerSubVec size =
        case size of
             1 => PackWord8Big.subVec  |
             2 => PackWord16Big.subVec |
             3 => PackWord24Big.subVec |
             4 => PackWord32Big.subVec |
             5 => PackWord40Big.subVec |
             6 => PackWord48Big.subVec |
             7 => PackWord56Big.subVec |
             8 => PackWord64Big.subVec |
              (* is not raised now, as the maximum
                  Word8Vector length is limited by 8 bytes *)
             _ => raise Overflow

      fun decodeStringLength input =
      let
        val base = 0wx80
        val inLen = Word8Vector.length input
        val prefix = Word8Vector.sub (input, 0)
      in
        if
          prefix < base
        then
          {len = 1, offset = 0, isList = false}

        else
          if
            prefix <= (base + 0w55)  andalso inLen > Word8.toInt (prefix - base)
          then
            let
              val strLen = Word8.toInt (prefix - base)
            in
              if
                strLen = 1 andalso Word8Vector.sub(input, 1) < base
              then
                raise RlpFormat "Single byte below 128 must be encoded as itself"
              else
                {len = strLen, offset = 1, isList = false}
            end

          else
            if
              prefix < (base + 0wx40) andalso inLen > Word8.toInt (prefix - (base + 0w55))
            then
              let
                val lenSize = Word8.toInt (prefix - (base + 0w55))
                val packerSubVec = getPackerSubVec lenSize

                val sizeBytes = Utils.takeVectorSlice (input, 1, SOME lenSize)
                val len = Int.fromLarge(
                  LargeWord.toLargeInt (packerSubVec (sizeBytes, 0))
                )
              in
                if
                  inLen > Word8.toInt (prefix - (base + 0w55)) + len
                then
                  if
                    Word8Vector.sub(input, 1) = 0w0
                  then
                    raise RlpFormat "Multi-byte length must have no leading zero"
                  else
                    if
                      len < 56
                    then
                      raise RlpFormat "Length below 56 must be encoded in one byte"
                    else
                      {len = len, offset = 1 + lenSize, isList = false}
                else
                  raise RlpFormat "Input don't conform RLP encoding form"
              end

            else
              raise RlpFormat "Input don't conform RLP encoding form"
      end

      fun decodeListLength input =
      let
        val base = 0wxc0
        val inLen = Word8Vector.length input
        val prefix = Word8Vector.sub (input, 0)
      in
        if
          prefix <= (base + 0w55) andalso inLen > Word8.toInt (prefix - base)
        then
          {len = Word8.toInt (prefix - base), offset = 1, isList = true}

        else
          if
            prefix < (base + 0wx40) andalso inLen > Word8.toInt (prefix - (base + 0w55))
          then
            let
              val lenSize = Word8.toInt (prefix - (base + 0w55))
              val packerSubVec = getPackerSubVec lenSize

              val sizeBytes = Utils.takeVectorSlice (input, 1, SOME lenSize)
              val len = Int.fromLarge(
                LargeWord.toLargeInt (packerSubVec (sizeBytes, 0))
              )
            in
              if
                inLen > Word8.toInt (prefix - (base + 0w55)) + len
              then
                if
                  Word8Vector.sub(input, 1) = 0w0
                then
                  raise RlpFormat "Multi-byte length must have no leading zero"
                else
                  if
                    len < 56
                  then
                    raise RlpFormat "Length below 56 must be encoded in one byte"
                  else
                    {len = len, offset = 1 + lenSize, isList = true}
              else
                raise RlpFormat "Input don't conform RLP encoding form"
            end

          else
            raise RlpFormat "Input don't conform RLP encoding form"
      end

    in
      fun decodeLength (input) =
        if
          Utils.isWord8VectorEmpty input
        then
           (* should not be raised as function in not called for empty vectors *)
          raise RlpFormat "Input is null"
        else
          let
            val prefix = Word8Vector.sub(input, 0)
          in
            if
              prefix < 0wxc0
            then
              decodeStringLength input
            else
              decodeListLength input
          end
    end

    fun formRlpResult (rawInput) =
      if
        Utils.isWord8VectorEmpty rawInput
      then
        raise RlpFormat "Input is null"
      else
        let
          val header = decodeLength (rawInput)
          val len = #len header
          val offset = #offset header
          val isList = #isList header
        in
          RlpResult({
            data = Utils.takeVectorSlice (rawInput, 0, SOME (offset + len)),
            len = Word64.fromInt len,
            offset = Word8.fromInt offset,
            isList = isList
          })
        end

     (* takes rlpResult as an argument *)
    fun decodeRlpString input =
    let
      val data = getRlpResultData input
      val offset = Word8.toInt (getRlpResultOffset input)
      val len = Word64.toInt (getRlpResultLength input)
      val isList = getRlpResultIsList input
    in
      if
        isList
      then
        raise RlpFormat "The input is rlp list"
      else
        if
          Word8Vector.length data <> (offset + len)
        then  (* not whole data is used from rlpResult *)
          raise RlpFormat "The rlpResult data is not fully used"
        else
          Utils.takeVectorSlice (data, offset, SOME len)
    end

     (* takes rlpResult as an argument *)
     (* transforms each item of list in rlpResult *)
    fun decodeRlpList input =
    let
      val data = getRlpResultData input
      val offset = Word8.toInt (getRlpResultOffset input)
      val len = Word64.toInt (getRlpResultLength input)
      val isList = getRlpResultIsList input

      fun decodeRlpListItems (input, currentResult) =
      let
        val item = formRlpResult (input)
        val itemOffset = Word8.toInt (getRlpResultOffset item)
        val itemLen = Word64.toInt (getRlpResultLength item)
        val itemSize = itemOffset + itemLen
        val remainingPart = Utils.takeVectorSlice (input, itemSize, NONE)
      in
        if
          Utils.isWord8VectorEmpty remainingPart
        then
          List.rev (item :: currentResult)
        else
          decodeRlpListItems (remainingPart, (item :: currentResult))
      end

      val headerlessData = Utils.takeVectorSlice (data, offset, NONE)
    in
      if
        not isList
      then
        raise RlpFormat "The input is rlp string"
      else
        if
          Word8Vector.length data <> (offset + len)
        then  (* not whole data is used from rlpResult *)
          raise RlpFormat "The rlpResult data is not fully used"
        else
          decodeRlpListItems (headerlessData, [])
    end

    fun decodeList input = decodeRlpList input

    fun decodeWord8Vector input = decodeRlpString input

    fun decodeString input = Byte.bytesToString (decodeRlpString input)

    fun decodeWord (input, wordSize) =
    let
      fun validateWord (decodedWord, wordSize) =
      let
        val decodedWordLen = Word8Vector.length decodedWord
        val _ =
          if (decodedWordLen = 0)
            then raise RlpFormat "Word should be at least one byte long"
            else ()
        val _ =
          if (decodedWordLen > 1) andalso (Word8Vector.sub(decodedWord, 0) = 0w0)
            then raise RlpFormat "Word should not contain leading zeros"
            else ()
        val _ =
          if decodedWordLen > wordSize
            then raise RlpFormat "Word should not be greater than decoding word size"
            else ()
      in
        ()
      end

      fun fillWithZeros (data, zerosCount) =
      let
        val padding = Word8Array.vector (Word8Array.array (zerosCount, 0w0))
      in
        Word8Vector.concat [padding, data]
      end

      val decodedWord = decodeRlpString input
      val _ = validateWord (decodedWord, wordSize)

      val zerosCount = wordSize - (Word8Vector.length decodedWord)
    in
      fillWithZeros (decodedWord, zerosCount)
    end

    fun decodeWord8 input =
      Utils.word8VectorToWord8 (decodeWord (input, 1))

    fun decodeWord16 input =
      Utils.word8VectorToWord16 (decodeWord (input, 2))

    fun decodeWord32 input =
      Utils.word8VectorToWord32 (decodeWord (input, 4))

    fun decodeWord64 input =
      Utils.word8VectorToWord64 (decodeWord (input, 8))

      end
end
