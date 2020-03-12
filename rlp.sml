local
  open Foreign
in
  val rlp_lib = loadLibrary "./libraries/rlp.so";

  val call = buildCall0((getSymbol rlp_lib "rlpCoderCreate"), (), cPointer);
  fun c_rlpCoderCreate() = call();

  val call = buildCall1((getSymbol rlp_lib "rlpCoderRelease"), cPointer, cVoid);
  fun c_rlpCoderRelease(coder) = call(coder);
end;

val coder = c_rlpCoderCreate();

c_rlpCoderRelease(coder);
