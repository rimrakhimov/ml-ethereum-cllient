signature PACK_WORD =
sig
    val bytesPerElem : int
    val isBigEndian : bool
    val subVec  : Word8Vector.vector * int -> LargeWord.word
    val subVecX : Word8Vector.vector * int -> LargeWord.word
    val subArr  : Word8Array.array * int -> LargeWord.word
    val subArrX : Word8Array.array * int -> LargeWord.word
    val update : Word8Array.array * int * LargeWord.word -> unit
end;

local
    infix << >>
    infix andb
    infix orb
    val op orb = LargeWord.orb
    and op << = LargeWord.<<
    and op >> = LargeWord.>>

    fun threeBytesToWord(high, medium, low) =
        (Word8.toLargeWord high << 0w16) orb
        (Word8.toLargeWord medium << 0w8) orb
        Word8.toLargeWord low

    fun threeBytesToWordX(high, medium, low) =
        (Word8.toLargeWordX high << 0w16) orb
        (Word8.toLargeWord medium << 0w8) orb
        Word8.toLargeWord low

in
    structure PackWord24Big : PACK_WORD =
    struct
        val bytesPerElem = 3
        val isBigEndian = true

        fun subVec(a, i) =
            threeBytesToWord(
                Word8Vector.sub(a, i*3), Word8Vector.sub(a, i*3+1),
                Word8Vector.sub(a, i*3+2))

        fun subVecX(a, i) =
            threeBytesToWordX(
                Word8Vector.sub(a, i*3), Word8Vector.sub(a, i*3+1),
                Word8Vector.sub(a, i*3+2))

        fun subArr(a, i) =
            threeBytesToWord(
                Word8Array.sub(a, i*3), Word8Array.sub(a, i*3+1),
                Word8Array.sub(a, i*3+2))

        fun subArrX(a, i) =
            threeBytesToWordX(
                Word8Array.sub(a, i*3), Word8Array.sub(a, i*3+1),
                Word8Array.sub(a, i*3+2))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*3+2 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*3+2, Word8.fromLargeWord v);
             Word8Array.update(a, i*3+1, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*3, Word8.fromLargeWord(v >> 0w16))
            )
    end;

    structure PackWord24Little : PACK_WORD =
    struct
        val bytesPerElem = 3
        val isBigEndian = false

        fun subVec(a, i) =
            threeBytesToWord(
                Word8Vector.sub(a, i*3+2), Word8Vector.sub(a, i*3+1),
                Word8Vector.sub(a, i*3))

        fun subVecX(a, i) =
            threeBytesToWordX(
                Word8Vector.sub(a, i*3+2), Word8Vector.sub(a, i*3+1),
                Word8Vector.sub(a, i*3))

        fun subArr(a, i) =
            threeBytesToWord(
                Word8Array.sub(a, i*3+2), Word8Array.sub(a, i*3+1),
                Word8Array.sub(a, i*3))

        fun subArrX(a, i) =
            threeBytesToWordX(
                Word8Array.sub(a, i*3+2), Word8Array.sub(a, i*3+1),
                Word8Array.sub(a, i*3))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*3+2 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*3, Word8.fromLargeWord v);
             Word8Array.update(a, i*3+1, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*3+2, Word8.fromLargeWord(v >> 0w16))
            )
    end;

end;


local
    infix << >>
    infix andb
    infix orb
    val op orb = LargeWord.orb
    and op << = LargeWord.<<
    and op >> = LargeWord.>>

    fun fiveBytesToWord(highest, higher, medium, lower, low) =
        (Word8.toLargeWord highest << 0w32) orb
        (Word8.toLargeWord higher << 0w24) orb
        (Word8.toLargeWord medium << 0w16) orb
        (Word8.toLargeWord lower << 0w8) orb
        Word8.toLargeWord low

    fun fiveBytesToWordX(highest, higher, medium, lower, low) =
        (Word8.toLargeWordX highest << 0w32) orb
        (Word8.toLargeWord higher << 0w24) orb
        (Word8.toLargeWord medium << 0w16) orb
        (Word8.toLargeWord lower << 0w8) orb
        Word8.toLargeWord low

in
    structure PackWord40Big : PACK_WORD =
    struct
        val bytesPerElem = 5
        val isBigEndian = true

        fun subVec(a, i) =
            fiveBytesToWord(
                Word8Vector.sub(a, i*5), Word8Vector.sub(a, i*5+1),
                Word8Vector.sub(a, i*5+2), Word8Vector.sub(a, i*5+3),
                Word8Vector.sub(a, i*5+4))

        fun subVecX(a, i) =
            fiveBytesToWordX(
                Word8Vector.sub(a, i*5), Word8Vector.sub(a, i*5+1),
                Word8Vector.sub(a, i*5+2), Word8Vector.sub(a, i*5+3),
                Word8Vector.sub(a, i*5+4))

        fun subArr(a, i) =
            fiveBytesToWord(
                Word8Array.sub(a, i*5), Word8Array.sub(a, i*5+1),
                Word8Array.sub(a, i*5+2), Word8Array.sub(a, i*5+3),
                Word8Array.sub(a, i*5+4))

        fun subArrX(a, i) =
            fiveBytesToWordX(
                Word8Array.sub(a, i*5), Word8Array.sub(a, i*5+1),
                Word8Array.sub(a, i*5+2), Word8Array.sub(a, i*5+3),
                Word8Array.sub(a, i*5+4))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*5+4 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*5+4, Word8.fromLargeWord v);
             Word8Array.update(a, i*5+3, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*5+2, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*5+1, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*5, Word8.fromLargeWord(v >> 0w32))
            )
    end;

    structure PackWord40Little : PACK_WORD =
    struct
        val bytesPerElem = 5
        val isBigEndian = false

        fun subVec(a, i) =
            fiveBytesToWord(
                Word8Vector.sub(a, i*5+4), Word8Vector.sub(a, i*5+3),
                Word8Vector.sub(a, i*5+2), Word8Vector.sub(a, i*5+1),
                Word8Vector.sub(a, i*5))

        fun subVecX(a, i) =
            fiveBytesToWordX(
                Word8Vector.sub(a, i*5+4), Word8Vector.sub(a, i*5+3),
                Word8Vector.sub(a, i*5+2), Word8Vector.sub(a, i*5+1),
                Word8Vector.sub(a, i*5))

        fun subArr(a, i) =
            fiveBytesToWord(
                Word8Array.sub(a, i*5+4), Word8Array.sub(a, i*5+3),
                Word8Array.sub(a, i*5+2), Word8Array.sub(a, i*5+1),
                Word8Array.sub(a, i*5))

        fun subArrX(a, i) =
            fiveBytesToWordX(
                Word8Array.sub(a, i*5+4), Word8Array.sub(a, i*5+3),
                Word8Array.sub(a, i*5+2), Word8Array.sub(a, i*5+1),
                Word8Array.sub(a, i*5))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*5+4 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*5, Word8.fromLargeWord v);
             Word8Array.update(a, i*5+1, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*5+2, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*5+3, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*5+4, Word8.fromLargeWord(v >> 0w32))
            )
    end

end;

local
    infix << >>
    infix andb
    infix orb
    val op orb = LargeWord.orb
    and op << = LargeWord.<<
    and op >> = LargeWord.>>

    fun sixBytesToWord(first, second, third, fourth, fifth, sixth) =
        (Word8.toLargeWord first << 0w40) orb
        (Word8.toLargeWord second << 0w32) orb
        (Word8.toLargeWord third << 0w24) orb
        (Word8.toLargeWord fourth << 0w16) orb
        (Word8.toLargeWord fifth << 0w8) orb
        Word8.toLargeWord sixth

    fun sixBytesToWordX(first, second, third, fourth, fifth, sixth) =
        (Word8.toLargeWordX first << 0w40) orb
        (Word8.toLargeWord second << 0w32) orb
        (Word8.toLargeWord third << 0w24) orb
        (Word8.toLargeWord fourth << 0w16) orb
        (Word8.toLargeWord fifth << 0w8) orb
        Word8.toLargeWord sixth

in
    structure PackWord48Big : PACK_WORD =
    struct
        val bytesPerElem = 6
        val isBigEndian = true

        fun subVec(a, i) =
            sixBytesToWord(
                Word8Vector.sub(a, i*6), Word8Vector.sub(a, i*6+1),
                Word8Vector.sub(a, i*6+2), Word8Vector.sub(a, i*6+3),
                Word8Vector.sub(a, i*6+4), Word8Vector.sub(a, i*6+5))

        fun subVecX(a, i) =
            sixBytesToWordX(
                Word8Vector.sub(a, i*6), Word8Vector.sub(a, i*6+1),
                Word8Vector.sub(a, i*6+2), Word8Vector.sub(a, i*6+3),
                Word8Vector.sub(a, i*6+4), Word8Vector.sub(a, i*6+5))

        fun subArr(a, i) =
            sixBytesToWord(
                Word8Array.sub(a, i*6), Word8Array.sub(a, i*6+1),
                Word8Array.sub(a, i*6+2), Word8Array.sub(a, i*6+3),
                Word8Array.sub(a, i*6+4), Word8Array.sub(a, i*6+5))

        fun subArrX(a, i) =
            sixBytesToWordX(
                Word8Array.sub(a, i*6), Word8Array.sub(a, i*6+1),
                Word8Array.sub(a, i*6+2), Word8Array.sub(a, i*6+3),
                Word8Array.sub(a, i*6+4), Word8Array.sub(a, i*6+5))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*6+5 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*6+5, Word8.fromLargeWord v);
             Word8Array.update(a, i*6+4, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*6+3, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*6+2, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*6+1, Word8.fromLargeWord(v >> 0w32));
             Word8Array.update(a, i*6, Word8.fromLargeWord(v >> 0w40))
            )
    end;

    structure PackWord48Little : PACK_WORD =
    struct
        val bytesPerElem = 6
        val isBigEndian = false

        fun subVec(a, i) =
            sixBytesToWord(
                Word8Vector.sub(a, i*6+5), Word8Vector.sub(a, i*6+4),
                Word8Vector.sub(a, i*6+3), Word8Vector.sub(a, i*6+2),
                Word8Vector.sub(a, i*6+1), Word8Vector.sub(a, i*6))

        fun subVecX(a, i) =
            sixBytesToWordX(
                Word8Vector.sub(a, i*6+5), Word8Vector.sub(a, i*6+4),
                Word8Vector.sub(a, i*6+3), Word8Vector.sub(a, i*6+2),
                Word8Vector.sub(a, i*6+1), Word8Vector.sub(a, i*6))

        fun subArr(a, i) =
            sixBytesToWord(
                Word8Array.sub(a, i*6+5), Word8Array.sub(a, i*6+4),
                Word8Array.sub(a, i*6+3), Word8Array.sub(a, i*6+2),
                Word8Array.sub(a, i*6+1), Word8Array.sub(a, i*6))

        fun subArrX(a, i) =
            sixBytesToWordX(
                Word8Array.sub(a, i*6+5), Word8Array.sub(a, i*6+4),
                Word8Array.sub(a, i*6+3), Word8Array.sub(a, i*6+2),
                Word8Array.sub(a, i*6+1), Word8Array.sub(a, i*6))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*6+5 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*6, Word8.fromLargeWord v);
             Word8Array.update(a, i*6+1, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*6+2, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*6+3, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*6+4, Word8.fromLargeWord(v >> 0w32));
             Word8Array.update(a, i*6+5, Word8.fromLargeWord(v >> 0w40))
            )
    end

end;


local
    infix << >>
    infix andb
    infix orb
    val op orb = LargeWord.orb
    and op << = LargeWord.<<
    and op >> = LargeWord.>>

    fun sevenBytesToWord(first, second, third, fourth, fifth, sixth, seventh) =
        (Word8.toLargeWord first << 0w48) orb
        (Word8.toLargeWord second << 0w40) orb
        (Word8.toLargeWord third << 0w32) orb
        (Word8.toLargeWord fourth << 0w24) orb
        (Word8.toLargeWord fifth << 0w16) orb
        (Word8.toLargeWord sixth << 0w8) orb
        Word8.toLargeWord seventh

    fun sevenBytesToWordX(first, second, third, fourth, fifth, sixth, seventh) =
        (Word8.toLargeWordX first << 0w48) orb
        (Word8.toLargeWord second << 0w40) orb
        (Word8.toLargeWord third << 0w32) orb
        (Word8.toLargeWord fourth << 0w24) orb
        (Word8.toLargeWord fifth << 0w16) orb
        (Word8.toLargeWord sixth << 0w8) orb
        Word8.toLargeWord seventh

in
    structure PackWord56Big : PACK_WORD =
    struct
        val bytesPerElem = 7
        val isBigEndian = true

        fun subVec(a, i) =
            sevenBytesToWord(
                Word8Vector.sub(a, i*7), Word8Vector.sub(a, i*7+1),
                Word8Vector.sub(a, i*7+2), Word8Vector.sub(a, i*7+3),
                Word8Vector.sub(a, i*7+4), Word8Vector.sub(a, i*7+5),
                Word8Vector.sub(a, i*7+6))

        fun subVecX(a, i) =
            sevenBytesToWordX(
                Word8Vector.sub(a, i*7), Word8Vector.sub(a, i*7+1),
                Word8Vector.sub(a, i*7+2), Word8Vector.sub(a, i*7+3),
                Word8Vector.sub(a, i*7+4), Word8Vector.sub(a, i*7+5),
                Word8Vector.sub(a, i*7+6))

        fun subArr(a, i) =
            sevenBytesToWord(
                Word8Array.sub(a, i*7), Word8Array.sub(a, i*7+1),
                Word8Array.sub(a, i*7+2), Word8Array.sub(a, i*7+3),
                Word8Array.sub(a, i*7+4), Word8Array.sub(a, i*7+5),
                Word8Array.sub(a, i*7+6))

        fun subArrX(a, i) =
            sevenBytesToWordX(
                Word8Array.sub(a, i*7), Word8Array.sub(a, i*7+1),
                Word8Array.sub(a, i*7+2), Word8Array.sub(a, i*7+3),
                Word8Array.sub(a, i*7+4), Word8Array.sub(a, i*7+5),
                Word8Array.sub(a, i*7+6))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*7+6 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*7+6, Word8.fromLargeWord v);
             Word8Array.update(a, i*7+5, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*7+4, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*7+3, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*7+2, Word8.fromLargeWord(v >> 0w32));
             Word8Array.update(a, i*7+1, Word8.fromLargeWord(v >> 0w40));
             Word8Array.update(a, i*7, Word8.fromLargeWord(v >> 0w48))
            )
    end;

    structure PackWord56Little : PACK_WORD =
    struct
        val bytesPerElem = 7
        val isBigEndian = false

        fun subVec(a, i) =
            sevenBytesToWord(
                Word8Vector.sub(a, i*7+6), Word8Vector.sub(a, i*7+5),
                Word8Vector.sub(a, i*7+4), Word8Vector.sub(a, i*7+3),
                Word8Vector.sub(a, i*7+2), Word8Vector.sub(a, i*7+1),
                Word8Vector.sub(a, i*7))

        fun subVecX(a, i) =
            sevenBytesToWordX(
                Word8Vector.sub(a, i*7+6), Word8Vector.sub(a, i*7+5),
                Word8Vector.sub(a, i*7+4), Word8Vector.sub(a, i*7+3),
                Word8Vector.sub(a, i*7+2), Word8Vector.sub(a, i*7+1),
                Word8Vector.sub(a, i*7))

        fun subArr(a, i) =
            sevenBytesToWord(
                Word8Array.sub(a, i*7+6), Word8Array.sub(a, i*7+5),
                Word8Array.sub(a, i*7+4), Word8Array.sub(a, i*7+3),
                Word8Array.sub(a, i*7+2), Word8Array.sub(a, i*7+1),
                Word8Array.sub(a, i*7))

        fun subArrX(a, i) =
            sevenBytesToWordX(
                Word8Array.sub(a, i*7+6), Word8Array.sub(a, i*7+5),
                Word8Array.sub(a, i*7+4), Word8Array.sub(a, i*7+3),
                Word8Array.sub(a, i*7+2), Word8Array.sub(a, i*7+1),
                Word8Array.sub(a, i*7))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*7+6 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*7, Word8.fromLargeWord v);
             Word8Array.update(a, i*7+1, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*7+2, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*7+3, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*7+4, Word8.fromLargeWord(v >> 0w32));
             Word8Array.update(a, i*7+5, Word8.fromLargeWord(v >> 0w40));
             Word8Array.update(a, i*7+6, Word8.fromLargeWord(v >> 0w48))
            )
    end

end;


local
    infix << >>
    infix andb
    infix orb
    val op orb = LargeWord.orb
    and op << = LargeWord.<<
    and op >> = LargeWord.>>

    fun eightBytesToWord(first, second, third, fourth, fifth, sixth, seventh, eighth) =
        (Word8.toLargeWord first << 0w56) orb
        (Word8.toLargeWord second << 0w48) orb
        (Word8.toLargeWord third << 0w40) orb
        (Word8.toLargeWord fourth << 0w32) orb
        (Word8.toLargeWord fifth << 0w24) orb
        (Word8.toLargeWord sixth << 0w16) orb
        (Word8.toLargeWord seventh << 0w8) orb
        Word8.toLargeWord eighth

    fun eightBytesToWordX(first, second, third, fourth, fifth, sixth, seventh, eighth) =
        (Word8.toLargeWordX first << 0w56) orb
        (Word8.toLargeWord second << 0w48) orb
        (Word8.toLargeWord third << 0w40) orb
        (Word8.toLargeWord fourth << 0w32) orb
        (Word8.toLargeWord fifth << 0w24) orb
        (Word8.toLargeWord sixth << 0w16) orb
        (Word8.toLargeWord seventh << 0w8) orb
        Word8.toLargeWord eighth

in
    structure PackWord56Big : PACK_WORD =
    struct
        val bytesPerElem = 8
        val isBigEndian = true

        fun subVec(a, i) =
            eightBytesToWord(
                Word8Vector.sub(a, i*8), Word8Vector.sub(a, i*8+1),
                Word8Vector.sub(a, i*8+2), Word8Vector.sub(a, i*8+3),
                Word8Vector.sub(a, i*8+4), Word8Vector.sub(a, i*8+5),
                Word8Vector.sub(a, i*8+6), Word8Vector.sub(a, i*8+7))

        fun subVecX(a, i) =
            eightBytesToWordX(
                Word8Vector.sub(a, i*8), Word8Vector.sub(a, i*8+1),
                Word8Vector.sub(a, i*8+2), Word8Vector.sub(a, i*8+3),
                Word8Vector.sub(a, i*8+4), Word8Vector.sub(a, i*8+5),
                Word8Vector.sub(a, i*8+6), Word8Vector.sub(a, i*8+7))

        fun subArr(a, i) =
            eightBytesToWord(
                Word8Array.sub(a, i*8), Word8Array.sub(a, i*8+1),
                Word8Array.sub(a, i*8+2), Word8Array.sub(a, i*8+3),
                Word8Array.sub(a, i*8+4), Word8Array.sub(a, i*8+5),
                Word8Array.sub(a, i*8+6), Word8Array.sub(a, i*8+7))

        fun subArrX(a, i) =
            eightBytesToWordX(
                Word8Array.sub(a, i*8), Word8Array.sub(a, i*8+1),
                Word8Array.sub(a, i*8+2), Word8Array.sub(a, i*8+3),
                Word8Array.sub(a, i*8+4), Word8Array.sub(a, i*8+5),
                Word8Array.sub(a, i*8+6), Word8Array.sub(a, i*8+7))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*8+7 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*8+7, Word8.fromLargeWord v);
             Word8Array.update(a, i*7+6, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*7+5, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*7+4, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*7+3, Word8.fromLargeWord(v >> 0w32));
             Word8Array.update(a, i*7+2, Word8.fromLargeWord(v >> 0w40));
             Word8Array.update(a, i*7+1, Word8.fromLargeWord(v >> 0w48));
             Word8Array.update(a, i*7, Word8.fromLargeWord(v >> 0w56))
            )
    end;

    structure PackWord56Little : PACK_WORD =
    struct
        val bytesPerElem = 8
        val isBigEndian = false

        fun subVec(a, i) =
            eightBytesToWord(
                Word8Vector.sub(a, i*8+7), Word8Vector.sub(a, i*8+6),
                Word8Vector.sub(a, i*8+5), Word8Vector.sub(a, i*8+4),
                Word8Vector.sub(a, i*8+3), Word8Vector.sub(a, i*8+2),
                Word8Vector.sub(a, i*8+1), Word8Vector.sub(a, i*8))

        fun subVecX(a, i) =
            eightBytesToWordX(
                Word8Vector.sub(a, i*8+7), Word8Vector.sub(a, i*8+6),
                Word8Vector.sub(a, i*8+5), Word8Vector.sub(a, i*8+4),
                Word8Vector.sub(a, i*8+3), Word8Vector.sub(a, i*8+2),
                Word8Vector.sub(a, i*8+1), Word8Vector.sub(a, i*8))

        fun subArr(a, i) =
            eightBytesToWord(
                Word8Array.sub(a, i*8+7), Word8Array.sub(a, i*8+6),
                Word8Array.sub(a, i*8+5), Word8Array.sub(a, i*8+4),
                Word8Array.sub(a, i*8+3), Word8Array.sub(a, i*8+2),
                Word8Array.sub(a, i*8+1), Word8Array.sub(a, i*8))

        fun subArrX(a, i) =
            eightBytesToWordX(
                Word8Array.sub(a, i*8+7), Word8Array.sub(a, i*8+6),
                Word8Array.sub(a, i*8+5), Word8Array.sub(a, i*8+4),
                Word8Array.sub(a, i*8+3), Word8Array.sub(a, i*8+2),
                Word8Array.sub(a, i*8+1), Word8Array.sub(a, i*8))

        fun update(a, i, v) =
            (* Check the index before doing any update. *)
            if i < 0 orelse i*8+7 >= Word8Array.length a
            then raise Subscript
            else
            (Word8Array.update(a, i*8, Word8.fromLargeWord v);
             Word8Array.update(a, i*8+1, Word8.fromLargeWord(v >> 0w8));
             Word8Array.update(a, i*8+2, Word8.fromLargeWord(v >> 0w16));
             Word8Array.update(a, i*8+3, Word8.fromLargeWord(v >> 0w24));
             Word8Array.update(a, i*8+4, Word8.fromLargeWord(v >> 0w32));
             Word8Array.update(a, i*8+5, Word8.fromLargeWord(v >> 0w40));
             Word8Array.update(a, i*8+6, Word8.fromLargeWord(v >> 0w48));
             Word8Array.update(a, i*8+7, Word8.fromLargeWord(v >> 0w56))
             )
    end

end;
