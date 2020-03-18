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
  end;
