structure Random =
struct
      (* Uses /dev/random and /dev/urandom to get a random word.
       * If they can't be read from, return NONE.
       * Taken from MLTon.Random structure,
       *  and modified to return vector instead of word.
       *)
      local
         fun make (file, name) len =
            let
               val buf = Word8Array.array (len, 0w0)
            in
               (* fn () => *)
               (let
                   val fd =
                      let
                         open Posix.FileSys
                      in
                         openf (file, O_RDONLY, O.flags [])
                      end
                   fun loop rem =
                      let
                         val n = Posix.IO.readArr (fd,
                                                   Word8ArraySlice.slice
                                                   (buf, len - rem, SOME rem))
                         val _ = if n = 0
                                    then (Posix.IO.close fd; raise Fail name)
                                 else ()
                         val rem = rem - n
                      in
                         if rem = 0
                            then ()
                         else loop rem
                      end
                   val _ = loop len
                   val _ = Posix.IO.close fd
                in
                   SOME (Word8Array.vector buf)
                end
                   handle OS.SysErr _ => NONE)
            end
      in
         fun seed len = make ("/dev/random", "Random.seed") len
         fun useed len = make ("/dev/urandom", "Random.useed") len
      end
end
