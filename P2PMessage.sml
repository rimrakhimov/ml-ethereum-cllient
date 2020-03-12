datatype capability = Capability of string*Word32.word;

datatype handshake = Handshake of
     Word64.word * string * capability list * Word64.word * Word64.word;

datatype p2pmessage = Hello of handshake | Disconnet
