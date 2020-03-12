fun println s =
    (print (s ^ "\n"); TextIO.flushOut TextIO.stdOut);

fun word8VectorToWord32 (word8VectorData) =
      Word8Vector.foldl (fn (item, result) => Word32.+ (Word32.<< (result, Word.fromInt(8)),
          Word32.fromInt (Word8.toInt item))) (Word32.fromInt 0) word8VectorData;

fun handleConn conn handler =
  let
    local
      fun recv maxNumberOfBytes =
        let
          val data = Socket.recvVec (conn, maxNumberOfBytes);
          val recvNumberOfBytes = Word8Vector.length data;
        in
          if recvNumberOfBytes = 0
            then (Socket.close conn; Thread.exit; () )
          else if Word8Vector.length < maxNumberOfBytes
            then Word8Vector.concat [data, (recv (maxNumberOfBytes -
                                        recvNumberOfBytes))]
            else data
        end;
    in
      fun recvWord32 =
        word8VectorToWord32 (recv 4);
    end;
    val a = recvWord32;
    val b = recvWord32;
  in
    Socket.close conn;
    a
  end;



fun serverForever masterSock handler =
  let
    val _ = println "Waiting for connection ...";
    fun fork conn =
      Thread.Thread.fork (fn () => handleConn conn handler, []);
    val (conn, _) = Socket.accept masterSock;
  in
    fork conn handler;
    serverForever masterSock handler;
    ()
  end;


fun listenAndServe port handler =
  let
    val masterSock = INetSock.TCP.socket();
    val sleep = OS.Process.sleep;
    fun bind () =
      let
        fun doBind() = Socket.bind (masterSock, INetSock.any port)
      in
        doBind() handle SysError => (sleep (Time.fromSeconds 1); bind());
        ()
      end;
  in
    println "Binding server...";
    bind();
    println ("Server bound... Listening on port " ^ (Int.toString port));
    Socket.listen (masterSock, 1024);
    Socket.Ctl.setREUSEADDR(masterSock, true);

    serverForever masterSock handler

  end;
