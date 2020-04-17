(* Test cases have been obtained from NIST examples:
 *  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_DRBG.pdf *)

use "libs/crypto/crypto";

fun testCase1 () =
let
  val algo = Crypto.SHA1

  val entropy = Word8Vector.fromList [
    0wx00, 0wx01, 0wx02, 0wx03, 0wx04, 0wx05, 0wx06, 0wx07,
    0wx08, 0wx09, 0wx0a, 0wx0b, 0wx0c, 0wx0d, 0wx0e, 0wx0f,
    0wx10, 0wx11, 0wx12, 0wx13, 0wx14, 0wx15, 0wx16, 0wx17,
    0wx18, 0wx19, 0wx1a, 0wx1b, 0wx1c, 0wx1d, 0wx1e, 0wx1f,
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e, 0wx2f,
    0wx30, 0wx31, 0wx32, 0wx33, 0wx34, 0wx35, 0wx36
  ]

  val nonce = Word8Vector.fromList [
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24
  ]

  val ps = Word8Vector.fromList []

  val drng = Crypto.HMAC_DRNG.init (algo, entropy, nonce, ps)

  val add_input = Word8Vector.fromList []

  val generatedOutput1 = Crypto.HMAC_DRNG.generate (drng, 40, add_input)
  val expectedOutput1 = Word8Vector.fromList [
    0wx5a, 0wx7d, 0wx3b, 0wx44, 0wx9f, 0wx48, 0wx1c, 0wxb3,
    0wx8d, 0wxf7, 0wx9a, 0wxd2, 0wxb1, 0wxfc, 0wxc0, 0wx1e,
    0wx57, 0wxf8, 0wx13, 0wx5e, 0wx8c, 0wx0b, 0wx22, 0wxcd,
    0wx06, 0wx30, 0wxbf, 0wxb0, 0wx12, 0wx7f, 0wxb5, 0wx40,
    0wx8c, 0wx8e, 0wxfc, 0wx17, 0wxa9, 0wx29, 0wx89, 0wx6e
  ]

  val generatedOutput2 = Crypto.HMAC_DRNG.generate(drng, 40, add_input)
  val expectedOutput2 = Word8Vector.fromList [
    0wx82, 0wxcf, 0wx77, 0wx2e, 0wxc3, 0wxe8, 0wx4b, 0wx00,
    0wxfc, 0wx74, 0wxf5, 0wxdf, 0wx10, 0wx4e, 0wxfb, 0wxfb,
    0wx24, 0wx28, 0wx55, 0wx4e, 0wx9c, 0wxe3, 0wx67, 0wxd0,
    0wx3a, 0wxea, 0wxde, 0wx37, 0wx82, 0wx7f, 0wxa8, 0wxe9,
    0wxcb, 0wx6a, 0wx08, 0wx19, 0wx61, 0wx15, 0wxd9, 0wx48
  ]

in
  if
    generatedOutput1 = expectedOutput1
  then
    if
      generatedOutput2 = expectedOutput2
    then
      print("    PASSED\n")
    else
      print("    FAILED: The second generated output does not match expected one\n")
  else
    print("    FAILED: The first generated output does not match expected one\n")
end


fun testCase2 () =
let
  val algo = Crypto.SHA512

  val entropy = Word8Vector.fromList [
    0wx00, 0wx01, 0wx02, 0wx03, 0wx04, 0wx05, 0wx06, 0wx07,
    0wx08, 0wx09, 0wx0a, 0wx0b, 0wx0c, 0wx0d, 0wx0e, 0wx0f,
    0wx10, 0wx11, 0wx12, 0wx13, 0wx14, 0wx15, 0wx16, 0wx17,
    0wx18, 0wx19, 0wx1a, 0wx1b, 0wx1c, 0wx1d, 0wx1e, 0wx1f,
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e, 0wx2f,
    0wx30, 0wx31, 0wx32, 0wx33, 0wx34, 0wx35, 0wx36, 0wx37,
    0wx38, 0wx39, 0wx3a, 0wx3b, 0wx3c, 0wx3d, 0wx3e, 0wx3f,
    0wx40, 0wx41, 0wx42, 0wx43, 0wx44, 0wx45, 0wx46, 0wx47,
    0wx48, 0wx49, 0wx4a, 0wx4b, 0wx4c, 0wx4d, 0wx4e, 0wx4f,
    0wx50, 0wx51, 0wx52, 0wx53, 0wx54, 0wx55, 0wx56, 0wx57,
    0wx58, 0wx59, 0wx5a, 0wx5b, 0wx5c, 0wx5d, 0wx5e, 0wx5f,
    0wx60, 0wx61, 0wx62, 0wx63, 0wx64, 0wx65, 0wx66, 0wx67,
    0wx68, 0wx69, 0wx6a, 0wx6b, 0wx6c, 0wx6d, 0wx6e
  ]

   (* for Reseed1 *)
  val entropy1 = Word8Vector.fromList [
    0wx80, 0wx81, 0wx82, 0wx83, 0wx84, 0wx85, 0wx86, 0wx87,
    0wx88, 0wx89, 0wx8a, 0wx8b, 0wx8c, 0wx8d, 0wx8e, 0wx8f,
    0wx90, 0wx91, 0wx92, 0wx93, 0wx94, 0wx95, 0wx96, 0wx97,
    0wx98, 0wx99, 0wx9a, 0wx9b, 0wx9c, 0wx9d, 0wx9e, 0wx9f,
    0wxa0, 0wxa1, 0wxa2, 0wxa3, 0wxa4, 0wxa5, 0wxa6, 0wxa7,
    0wxa8, 0wxa9, 0wxaa, 0wxab, 0wxac, 0wxad, 0wxae, 0wxaf,
    0wxb0, 0wxb1, 0wxb2, 0wxb3, 0wxb4, 0wxb5, 0wxb6, 0wxb7,
    0wxb8, 0wxb9, 0wxba, 0wxbb, 0wxbc, 0wxbd, 0wxbe, 0wxbf,
    0wxc0, 0wxc1, 0wxc2, 0wxc3, 0wxc4, 0wxc5, 0wxc6, 0wxc7,
    0wxc8, 0wxc9, 0wxca, 0wxcb, 0wxcc, 0wxcd, 0wxce, 0wxcf,
    0wxd0, 0wxd1, 0wxd2, 0wxd3, 0wxd4, 0wxd5, 0wxd6, 0wxd7,
    0wxd8, 0wxd9, 0wxda, 0wxdb, 0wxdc, 0wxdd, 0wxde, 0wxdf,
    0wxe0, 0wxe1, 0wxe2, 0wxe3, 0wxe4, 0wxe5, 0wxe6, 0wxe7,
    0wxe8, 0wxe9, 0wxea, 0wxeb, 0wxec, 0wxed, 0wxee
  ]

   (* for Reseed2 *)
  val entropy2 = Word8Vector.fromList [
    0wxc0, 0wxc1, 0wxc2, 0wxc3, 0wxc4, 0wxc5, 0wxc6, 0wxc7,
    0wxc8, 0wxc9, 0wxca, 0wxcb, 0wxcc, 0wxcd, 0wxce, 0wxcf,
    0wxd0, 0wxd1, 0wxd2, 0wxd3, 0wxd4, 0wxd5, 0wxd6, 0wxd7,
    0wxd8, 0wxd9, 0wxda, 0wxdb, 0wxdc, 0wxdd, 0wxde, 0wxdf,
    0wxe0, 0wxe1, 0wxe2, 0wxe3, 0wxe4, 0wxe5, 0wxe6, 0wxe7,
    0wxe8, 0wxe9, 0wxea, 0wxeb, 0wxec, 0wxed, 0wxee, 0wxef,
    0wxf0, 0wxf1, 0wxf2, 0wxf3, 0wxf4, 0wxf5, 0wxf6, 0wxf7,
    0wxf8, 0wxf9, 0wxfa, 0wxfb, 0wxfc, 0wxfd, 0wxfe, 0wxff,
    0wx00, 0wx01, 0wx02, 0wx03, 0wx04, 0wx05, 0wx06, 0wx07,
    0wx08, 0wx09, 0wx0a, 0wx0b, 0wx0c, 0wx0d, 0wx0e, 0wx0f,
    0wx10, 0wx11, 0wx12, 0wx13, 0wx14, 0wx15, 0wx16, 0wx17,
    0wx18, 0wx19, 0wx1a, 0wx1b, 0wx1c, 0wx1d, 0wx1e, 0wx1f,
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e
  ]

  val nonce = Word8Vector.fromList [
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e, 0wx2f
 ]

  val ps = Word8Vector.fromList [
    0wx40, 0wx41, 0wx42, 0wx43, 0wx44, 0wx45, 0wx46, 0wx47,
    0wx48, 0wx49, 0wx4a, 0wx4b, 0wx4c, 0wx4d, 0wx4e, 0wx4f,
    0wx50, 0wx51, 0wx52, 0wx53, 0wx54, 0wx55, 0wx56, 0wx57,
    0wx58, 0wx59, 0wx5a, 0wx5b, 0wx5c, 0wx5d, 0wx5e, 0wx5f,
    0wx60, 0wx61, 0wx62, 0wx63, 0wx64, 0wx65, 0wx66, 0wx67,
    0wx68, 0wx69, 0wx6a, 0wx6b, 0wx6c, 0wx6d, 0wx6e, 0wx6f,
    0wx70, 0wx71, 0wx72, 0wx73, 0wx74, 0wx75, 0wx76, 0wx77,
    0wx78, 0wx79, 0wx7a, 0wx7b, 0wx7c, 0wx7d, 0wx7e, 0wx7f,
    0wx80, 0wx81, 0wx82, 0wx83, 0wx84, 0wx85, 0wx86, 0wx87,
    0wx88, 0wx89, 0wx8a, 0wx8b, 0wx8c, 0wx8d, 0wx8e, 0wx8f,
    0wx90, 0wx91, 0wx92, 0wx93, 0wx94, 0wx95, 0wx96, 0wx97,
    0wx98, 0wx99, 0wx9a, 0wx9b, 0wx9c, 0wx9d, 0wx9e, 0wx9f,
    0wxa0, 0wxa1, 0wxa2, 0wxa3, 0wxa4, 0wxa5, 0wxa6, 0wxa7,
    0wxa8, 0wxa9, 0wxaa, 0wxab, 0wxac, 0wxad, 0wxae
  ]

  val add_input1 = Word8Vector.fromList [
    0wx60, 0wx61, 0wx62, 0wx63, 0wx64, 0wx65, 0wx66, 0wx67,
    0wx68, 0wx69, 0wx6a, 0wx6b, 0wx6c, 0wx6d, 0wx6e, 0wx6f,
    0wx70, 0wx71, 0wx72, 0wx73, 0wx74, 0wx75, 0wx76, 0wx77,
    0wx78, 0wx79, 0wx7a, 0wx7b, 0wx7c, 0wx7d, 0wx7e, 0wx7f,
    0wx80, 0wx81, 0wx82, 0wx83, 0wx84, 0wx85, 0wx86, 0wx87,
    0wx88, 0wx89, 0wx8a, 0wx8b, 0wx8c, 0wx8d, 0wx8e, 0wx8f,
    0wx90, 0wx91, 0wx92, 0wx93, 0wx94, 0wx95, 0wx96, 0wx97,
    0wx98, 0wx99, 0wx9a, 0wx9b, 0wx9c, 0wx9d, 0wx9e, 0wx9f,
    0wxa0, 0wxa1, 0wxa2, 0wxa3, 0wxa4, 0wxa5, 0wxa6, 0wxa7,
    0wxa8, 0wxa9, 0wxaa, 0wxab, 0wxac, 0wxad, 0wxae, 0wxaf,
    0wxb0, 0wxb1, 0wxb2, 0wxb3, 0wxb4, 0wxb5, 0wxb6, 0wxb7,
    0wxb8, 0wxb9, 0wxba, 0wxbb, 0wxbc, 0wxbd, 0wxbe, 0wxbf,
    0wxc0, 0wxc1, 0wxc2, 0wxc3, 0wxc4, 0wxc5, 0wxc6, 0wxc7,
    0wxc8, 0wxc9, 0wxca, 0wxcb, 0wxcc, 0wxcd, 0wxce
  ]

  val add_input2 = Word8Vector.fromList [
    0wxa0, 0wxa1, 0wxa2, 0wxa3, 0wxa4, 0wxa5, 0wxa6, 0wxa7,
    0wxa8, 0wxa9, 0wxaa, 0wxab, 0wxac, 0wxad, 0wxae, 0wxaf,
    0wxb0, 0wxb1, 0wxb2, 0wxb3, 0wxb4, 0wxb5, 0wxb6, 0wxb7,
    0wxb8, 0wxb9, 0wxba, 0wxbb, 0wxbc, 0wxbd, 0wxbe, 0wxbf,
    0wxc0, 0wxc1, 0wxc2, 0wxc3, 0wxc4, 0wxc5, 0wxc6, 0wxc7,
    0wxc8, 0wxc9, 0wxca, 0wxcb, 0wxcc, 0wxcd, 0wxce, 0wxcf,
    0wxd0, 0wxd1, 0wxd2, 0wxd3, 0wxd4, 0wxd5, 0wxd6, 0wxd7,
    0wxd8, 0wxd9, 0wxda, 0wxdb, 0wxdc, 0wxdd, 0wxde, 0wxdf,
    0wxe0, 0wxe1, 0wxe2, 0wxe3, 0wxe4, 0wxe5, 0wxe6, 0wxe7,
    0wxe8, 0wxe9, 0wxea, 0wxeb, 0wxec, 0wxed, 0wxee, 0wxef,
    0wxf0, 0wxf1, 0wxf2, 0wxf3, 0wxf4, 0wxf5, 0wxf6, 0wxf7,
    0wxf8, 0wxf9, 0wxfa, 0wxfb, 0wxfc, 0wxfd, 0wxfe, 0wxff,
    0wx00, 0wx01, 0wx02, 0wx03, 0wx04, 0wx05, 0wx06, 0wx07,
    0wx08, 0wx09, 0wx0a, 0wx0b, 0wx0c, 0wx0d, 0wx0e
  ]

  val drng = Crypto.HMAC_DRNG.init (algo, entropy, nonce, ps)

  val generatedOutput1 = Crypto.HMAC_DRNG.generate (drng, 128, add_input1)
  val expectedOutput1 = Word8Vector.fromList [
    0wx7a, 0wxe3, 0wx1a, 0wx2d, 0wxec, 0wx31, 0wx07, 0wx5f,
    0wxe5, 0wx97, 0wx26, 0wx60, 0wxc1, 0wx6d, 0wx22, 0wxec,
    0wxc0, 0wxd4, 0wx15, 0wxc5, 0wx69, 0wx30, 0wx01, 0wxbe,
    0wx5a, 0wx46, 0wx8b, 0wx59, 0wx0b, 0wxc1, 0wxae, 0wx2c,
    0wx43, 0wxf6, 0wx47, 0wxf8, 0wxd6, 0wx81, 0wxae, 0wxea,
    0wx0d, 0wx87, 0wxb7, 0wx9b, 0wx0b, 0wx4e, 0wx5d, 0wx08,
    0wx9c, 0wxa2, 0wxc9, 0wxd3, 0wx27, 0wx53, 0wx42, 0wx34,
    0wx02, 0wx54, 0wxe6, 0wxb0, 0wx46, 0wx90, 0wxd7, 0wx7a,
    0wx71, 0wxa2, 0wx94, 0wxda, 0wx95, 0wx68, 0wx47, 0wx9e,
    0wxef, 0wx8b, 0wxb2, 0wxa2, 0wx11, 0wx0f, 0wx18, 0wxb6,
    0wx22, 0wxf6, 0wx0f, 0wx35, 0wx23, 0wx5d, 0wxe0, 0wxe8,
    0wxf9, 0wxd7, 0wxe9, 0wx81, 0wx05, 0wxd8, 0wx4a, 0wxa2,
    0wx4a, 0wxf0, 0wx75, 0wx7a, 0wxf0, 0wx05, 0wxdf, 0wxd5,
    0wx2f, 0wxa5, 0wx1d, 0wxe3, 0wxf4, 0wx4f, 0wxce, 0wx0c,
    0wx5f, 0wx3a, 0wx27, 0wxfc, 0wxe8, 0wxb0, 0wxf6, 0wxe4,
    0wxa3, 0wxf7, 0wxc7, 0wxb5, 0wx3c, 0wxe3, 0wx4a, 0wx3d
  ]

  val generatedOutput2 = Crypto.HMAC_DRNG.generate(drng, 128, add_input2)
  val expectedOutput2 = Word8Vector.fromList [
    0wxd8, 0wx3a, 0wx80, 0wx84, 0wx63, 0wx0f, 0wx28, 0wx6d,
    0wxa4, 0wxdb, 0wx49, 0wxb9, 0wxf6, 0wxf6, 0wx08, 0wxc8,
    0wx99, 0wx3f, 0wx7f, 0wx13, 0wx97, 0wxea, 0wx0d, 0wx6f,
    0wx4a, 0wx72, 0wxcf, 0wx3e, 0wxf2, 0wx73, 0wx3a, 0wx11,
    0wxab, 0wx82, 0wx3c, 0wx29, 0wxf2, 0wxeb, 0wxde, 0wxc3,
    0wxed, 0wxe9, 0wx62, 0wxf9, 0wx3d, 0wx92, 0wx0a, 0wx1d,
    0wxb5, 0wx9c, 0wx84, 0wxe1, 0wxe8, 0wx79, 0wxc2, 0wx9f,
    0wx5f, 0wx99, 0wx95, 0wxfc, 0wx3a, 0wx6a, 0wx3a, 0wxf9,
    0wxb5, 0wx87, 0wxca, 0wx7c, 0wx13, 0wxea, 0wx19, 0wx7d,
    0wx42, 0wx3e, 0wx81, 0wxe1, 0wxd6, 0wx46, 0wx99, 0wx42,
    0wxb6, 0wxe2, 0wxca, 0wx83, 0wxa9, 0wx7e, 0wx91, 0wxf6,
    0wxb2, 0wx98, 0wx26, 0wx6a, 0wxc1, 0wx48, 0wxa1, 0wx80,
    0wx97, 0wx76, 0wxc2, 0wx6a, 0wxf5, 0wxe2, 0wx39, 0wxa5,
    0wx5a, 0wx2b, 0wxeb, 0wx9e, 0wx75, 0wx22, 0wx03, 0wxa6,
    0wx94, 0wxe1, 0wxf3, 0wxfe, 0wx2b, 0wx3e, 0wx6a, 0wx0c,
    0wx9c, 0wx31, 0wx44, 0wx21, 0wxcd, 0wxb5, 0wx5f, 0wxbd
  ]

in
  print("\nTest Case 2:\n");
  if
    generatedOutput1 = expectedOutput1
  then
    if
      generatedOutput2 = expectedOutput2
    then
      print("    PASSED\n")
    else
      print("    FAILED: The second generated output does not match expected one\n")
  else
    print("    FAILED: The first generated output does not match expected one\n")
end


fun testCase3 () =
let
  val algo = Crypto.SHA512

  val entropy = Word8Vector.fromList [
    0wx00, 0wx01, 0wx02, 0wx03, 0wx04, 0wx05, 0wx06, 0wx07,
    0wx08, 0wx09, 0wx0a, 0wx0b, 0wx0c, 0wx0d, 0wx0e, 0wx0f,
    0wx10, 0wx11, 0wx12, 0wx13, 0wx14, 0wx15, 0wx16, 0wx17,
    0wx18, 0wx19, 0wx1a, 0wx1b, 0wx1c, 0wx1d, 0wx1e, 0wx1f,
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e, 0wx2f,
    0wx30, 0wx31, 0wx32, 0wx33, 0wx34, 0wx35, 0wx36, 0wx37,
    0wx38, 0wx39, 0wx3a, 0wx3b, 0wx3c, 0wx3d, 0wx3e, 0wx3f,
    0wx40, 0wx41, 0wx42, 0wx43, 0wx44, 0wx45, 0wx46, 0wx47,
    0wx48, 0wx49, 0wx4a, 0wx4b, 0wx4c, 0wx4d, 0wx4e, 0wx4f,
    0wx50, 0wx51, 0wx52, 0wx53, 0wx54, 0wx55, 0wx56, 0wx57,
    0wx58, 0wx59, 0wx5a, 0wx5b, 0wx5c, 0wx5d, 0wx5e, 0wx5f,
    0wx60, 0wx61, 0wx62, 0wx63, 0wx64, 0wx65, 0wx66, 0wx67,
    0wx68, 0wx69, 0wx6a, 0wx6b, 0wx6c, 0wx6d, 0wx6e
  ]

   (* for Reseed1 *)
  val entropy1 = Word8Vector.fromList [
    0wx80, 0wx81, 0wx82, 0wx83, 0wx84, 0wx85, 0wx86, 0wx87,
    0wx88, 0wx89, 0wx8a, 0wx8b, 0wx8c, 0wx8d, 0wx8e, 0wx8f,
    0wx90, 0wx91, 0wx92, 0wx93, 0wx94, 0wx95, 0wx96, 0wx97,
    0wx98, 0wx99, 0wx9a, 0wx9b, 0wx9c, 0wx9d, 0wx9e, 0wx9f,
    0wxa0, 0wxa1, 0wxa2, 0wxa3, 0wxa4, 0wxa5, 0wxa6, 0wxa7,
    0wxa8, 0wxa9, 0wxaa, 0wxab, 0wxac, 0wxad, 0wxae, 0wxaf,
    0wxb0, 0wxb1, 0wxb2, 0wxb3, 0wxb4, 0wxb5, 0wxb6, 0wxb7,
    0wxb8, 0wxb9, 0wxba, 0wxbb, 0wxbc, 0wxbd, 0wxbe, 0wxbf,
    0wxc0, 0wxc1, 0wxc2, 0wxc3, 0wxc4, 0wxc5, 0wxc6, 0wxc7,
    0wxc8, 0wxc9, 0wxca, 0wxcb, 0wxcc, 0wxcd, 0wxce, 0wxcf,
    0wxd0, 0wxd1, 0wxd2, 0wxd3, 0wxd4, 0wxd5, 0wxd6, 0wxd7,
    0wxd8, 0wxd9, 0wxda, 0wxdb, 0wxdc, 0wxdd, 0wxde, 0wxdf,
    0wxe0, 0wxe1, 0wxe2, 0wxe3, 0wxe4, 0wxe5, 0wxe6, 0wxe7,
    0wxe8, 0wxe9, 0wxea, 0wxeb, 0wxec, 0wxed, 0wxee
  ]

   (* for Reseed2 *)
  val entropy2 = Word8Vector.fromList [
    0wxc0, 0wxc1, 0wxc2, 0wxc3, 0wxc4, 0wxc5, 0wxc6, 0wxc7,
    0wxc8, 0wxc9, 0wxca, 0wxcb, 0wxcc, 0wxcd, 0wxce, 0wxcf,
    0wxd0, 0wxd1, 0wxd2, 0wxd3, 0wxd4, 0wxd5, 0wxd6, 0wxd7,
    0wxd8, 0wxd9, 0wxda, 0wxdb, 0wxdc, 0wxdd, 0wxde, 0wxdf,
    0wxe0, 0wxe1, 0wxe2, 0wxe3, 0wxe4, 0wxe5, 0wxe6, 0wxe7,
    0wxe8, 0wxe9, 0wxea, 0wxeb, 0wxec, 0wxed, 0wxee, 0wxef,
    0wxf0, 0wxf1, 0wxf2, 0wxf3, 0wxf4, 0wxf5, 0wxf6, 0wxf7,
    0wxf8, 0wxf9, 0wxfa, 0wxfb, 0wxfc, 0wxfd, 0wxfe, 0wxff,
    0wx00, 0wx01, 0wx02, 0wx03, 0wx04, 0wx05, 0wx06, 0wx07,
    0wx08, 0wx09, 0wx0a, 0wx0b, 0wx0c, 0wx0d, 0wx0e, 0wx0f,
    0wx10, 0wx11, 0wx12, 0wx13, 0wx14, 0wx15, 0wx16, 0wx17,
    0wx18, 0wx19, 0wx1a, 0wx1b, 0wx1c, 0wx1d, 0wx1e, 0wx1f,
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e
  ]

  val nonce = Word8Vector.fromList [
    0wx20, 0wx21, 0wx22, 0wx23, 0wx24, 0wx25, 0wx26, 0wx27,
    0wx28, 0wx29, 0wx2a, 0wx2b, 0wx2c, 0wx2d, 0wx2e, 0wx2f
 ]

  val ps = Word8Vector.fromList []

  val add_input = Word8Vector.fromList []

  val drng = Crypto.HMAC_DRNG.init (algo, entropy, nonce, ps)

  val _ = Crypto.HMAC_DRNG.reseed (drng, entropy1, add_input)
  val generatedOutput1 = Crypto.HMAC_DRNG.generate (drng, 128, add_input)
  val expectedOutput1 = Word8Vector.fromList [
    0wx28, 0wxfd, 0wx60, 0wx60, 0wxc4, 0wxf3, 0wx5f, 0wx4d,
    0wx31, 0wx7a, 0wxb2, 0wx06, 0wx0e, 0wxe3, 0wx20, 0wx19,
    0wxe0, 0wxda, 0wxa3, 0wx30, 0wxf3, 0wxf5, 0wx65, 0wx0b,
    0wxbc, 0wxa5, 0wx7c, 0wxb6, 0wx7e, 0wxe6, 0wxaf, 0wx1c,
    0wx6f, 0wx25, 0wxd1, 0wxb0, 0wx1f, 0wx36, 0wx01, 0wxed,
    0wxa8, 0wx5d, 0wxc2, 0wxed, 0wx29, 0wxa9, 0wxb2, 0wxba,
    0wx4c, 0wx85, 0wxcf, 0wx49, 0wx1c, 0wxe7, 0wx18, 0wx5f,
    0wx1a, 0wx2b, 0wxd9, 0wx37, 0wx8a, 0wxe3, 0wxc6, 0wx55,
    0wxbd, 0wx1c, 0wxec, 0wx2e, 0wxe1, 0wx08, 0wxae, 0wx7f,
    0wxc3, 0wx82, 0wx98, 0wx9f, 0wx6d, 0wx4f, 0wxea, 0wx8a,
    0wxb0, 0wx14, 0wx99, 0wx69, 0wx7c, 0wx2f, 0wx07, 0wx94,
    0wx5c, 0wxe0, 0wx2c, 0wx5e, 0wxd6, 0wx17, 0wxd0, 0wx42,
    0wx87, 0wxfe, 0wxaf, 0wx3b, 0wxa6, 0wx38, 0wxa4, 0wxce,
    0wxf3, 0wxbb, 0wx6b, 0wx82, 0wx7e, 0wx40, 0wxaf, 0wx16,
    0wx27, 0wx95, 0wx80, 0wxfc, 0wxf1, 0wxfd, 0wxad, 0wx83,
    0wx09, 0wx30, 0wxf7, 0wxfd, 0wxe3, 0wx41, 0wxe2, 0wxaf
  ]

  val _ = Crypto.HMAC_DRNG.reseed (drng, entropy2, add_input)
  val generatedOutput2 = Crypto.HMAC_DRNG.generate(drng, 128, add_input)
  val expectedOutput2 = Word8Vector.fromList [
    0wxc0, 0wxb1, 0wx60, 0wx1a, 0wxfe, 0wx39, 0wx33, 0wx8b,
    0wx58, 0wxdc, 0wx2b, 0wxe7, 0wxc2, 0wx56, 0wxae, 0wxbe,
    0wx3c, 0wx21, 0wxc5, 0wxa9, 0wx39, 0wxbe, 0wxec, 0wx7e,
    0wx97, 0wxb3, 0wx52, 0wx8a, 0wxc4, 0wx20, 0wxf0, 0wxc6,
    0wx34, 0wx18, 0wx47, 0wx18, 0wx76, 0wx66, 0wxe0, 0wxff,
    0wx57, 0wx8a, 0wx8e, 0wxb0, 0wxa3, 0wx78, 0wx09, 0wxf8,
    0wx77, 0wx36, 0wx5a, 0wx28, 0wxdf, 0wx2f, 0wxa0, 0wxf0,
    0wx63, 0wx54, 0wxa6, 0wxf0, 0wx24, 0wx96, 0wx74, 0wx73,
    0wx69, 0wx37, 0wx5b, 0wx9a, 0wx9d, 0wx6b, 0wx75, 0wx6f,
    0wxdc, 0wx4a, 0wx8f, 0wxb3, 0wx08, 0wxe0, 0wx82, 0wx56,
    0wx9d, 0wx79, 0wxa8, 0wx5b, 0wxb9, 0wx60, 0wxf7, 0wx47,
    0wx25, 0wx66, 0wx26, 0wx38, 0wx9a, 0wx3b, 0wx45, 0wxb0,
    0wxab, 0wxe7, 0wxec, 0wxbc, 0wx39, 0wxd5, 0wxcd, 0wx7b,
    0wx2c, 0wx18, 0wxdf, 0wx2e, 0wx5f, 0wxde, 0wx8c, 0wx9b,
    0wx8d, 0wx43, 0wx47, 0wx4c, 0wx54, 0wxb6, 0wxf9, 0wx83,
    0wx94, 0wx68, 0wx44, 0wx59, 0wx29, 0wxb4, 0wx38, 0wxc7
  ]

in
  print("\nTest Case 3:\n");
  if
    generatedOutput1 = expectedOutput1
  then
    if
      generatedOutput2 = expectedOutput2
    then
      print("    PASSED\n")
    else
      print("    FAILED: The second generated output does not match expected one\n")
  else
    print("    FAILED: The first generated output does not match expected one\n")
end

fun main () =
let
  val _ = testCase1 ()
  val _ = testCase2 ()
  val _ = testCase3 ()
in
  ()
end
