open Gsasl_bindings

let c_headers = "#include <gsasl.h>"

let main () =
  let ml_out = open_out "lib/gsasl_generated.ml" in
  let c_out = open_out "lib/gsasl_stubs.c" in
  let ml_fmt = Format.formatter_of_out_channel ml_out in
  let c_fmt = Format.formatter_of_out_channel c_out in
  Cstubs.write_ml ml_fmt ~prefix:"libgsasl_" (module Bindings);
  Format.fprintf c_fmt "%s@\n" c_headers;
  Cstubs.write_c c_fmt ~prefix:"libgsasl_" (module Bindings);
  Format.pp_print_flush ml_fmt ();
  Format.pp_print_flush c_fmt ();
  close_out ml_out;
  close_out c_out

let () =
  main ()
