(*signature S1 =
sig
  type a
  fun
end *)

structure Struct1 =
struct
  datatype a = A1 of int
  fun getv (A1(v)) = v

  structure Struct2 =
  struct
    fun create (v) = A1(v)

    fun compare (v1, v2) =
      if getv (v1) > getv (v2)
      then v1
      else v2
  end
end
