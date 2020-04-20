use "P2PMessage";

val c1 = Capability("p2p", 0w5);
val c2 = Capability("les", 0w4);
val c3 = Capability ("eth", 0w2);

val hand = Handshake(0w5, "clm", [c1, c2, c3], 0w1235, 0w3452);
val enc = encodeHandshake hand;
val data = Rlp.getRlpResultData enc;

val decodedHand = decodeHandshake data;

decodedHand = hand;
