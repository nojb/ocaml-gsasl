open Ctypes
open Foreign

type gsasl_t
type gsasl_session_t

let gsasl : gsasl_t structure typ = structure "Gsasl"
let gsasl_session : gsasl_session_t structure typ = structure "Gsasl_session"

let gsasl_null = from_voidp gsasl null
let gsasl_session_null = from_voidp gsasl_session null

module Bindings (F : Cstubs.FOREIGN) = struct
  let gsasl_finish =
    F.foreign "gsasl_finish" (ptr gsasl_session @-> returning void)

  let gsasl_done =
    F.foreign "gsasl_done" (ptr gsasl @-> returning void)

  let gsasl_strerror =
    F.foreign "gsasl_strerror" (int @-> returning string)

  let gsasl_free =
    F.foreign "gsasl_free" (ptr void @-> returning void)

  let gsasl_check_version =
    F.foreign "gsasl_check_version" (string_opt @-> returning string_opt)

  let gsasl_init =
    F.foreign "gsasl_init" (ptr (ptr gsasl) @-> returning int)

  let gsasl_client_mechlist =
    F.foreign "gsasl_client_mechlist" (ptr gsasl @-> ptr (ptr char) @-> returning int)

  let gsasl_server_mechlist =
    F.foreign "gsasl_server_mechlist" (ptr gsasl @-> ptr (ptr char) @-> returning int)
      
  let gsasl_client_support_p =
    F.foreign "gsasl_client_support_p" (ptr gsasl @-> string @-> returning int)
      
  let gsasl_client_suggest_mechanism =
    F.foreign "gsasl_client_suggest_mechanism" (ptr gsasl @-> string @-> returning string_opt)
      
  let gsasl_encode =
    F.foreign "gsasl_encode"
      (ptr gsasl_session @-> string @-> int @-> ptr (ptr char) @-> ptr size_t @-> returning int)
      
  let gsasl_decode =
    F.foreign "gsasl_decode"
      (ptr gsasl_session @-> string @-> int @-> ptr (ptr char) @-> ptr size_t @-> returning int)
      
  let gsasl_client_start =
    F.foreign "gsasl_client_start"
      (ptr gsasl @-> string @-> ptr (ptr gsasl_session) @-> returning int)
      
  let gsasl_server_start =
    F.foreign "gsasl_server_start"
      (ptr gsasl @-> string @-> ptr (ptr gsasl_session) @-> returning int)
      
  let gsasl_mechanism_name =
    F.foreign "gsasl_mechanism_name" (ptr gsasl_session @-> returning string_opt)
      
  let gsasl_property_set_raw =
    F.foreign "gsasl_property_set_raw"
      (ptr gsasl_session @-> int @-> string @-> int @-> returning void)
      
  let gsasl_property_get =
    F.foreign "gsasl_property_get" (ptr gsasl_session @-> int @-> returning string_opt)
      
  let gsasl_step =
    F.foreign "gsasl_step"
      (ptr gsasl_session @-> string @-> int @-> ptr (ptr_opt char) @-> ptr size_t @-> returning int)
      
  let gsasl_step64 =
    F.foreign "gsasl_step64"
      (ptr gsasl_session @-> string @-> ptr (ptr_opt char) @-> returning int)
      
  let gsasl_callback_set =
    F.foreign "gsasl_callback_set"
      (ptr gsasl @-> funptr (ptr gsasl @-> ptr gsasl_session @-> int @-> returning int) @->
       returning void)
      
  let gsasl_saslprep =
    F.foreign "gsasl_saslprep" (string @-> int @-> ptr (ptr char) @-> ptr int @-> returning int)
      
  let gsasl_base64_to =
    F.foreign "gsasl_base64_to"
      (string @-> int @-> ptr (ptr char) @-> ptr size_t @-> returning int)
      
  let gsasl_base64_from =
    F.foreign "gsasl_base64_from"
      (string @-> int @-> ptr (ptr char) @-> ptr size_t @-> returning int)
      
  let gsasl_nonce =
    F.foreign "gsasl_nonce" (ptr char @-> int @-> returning int)
      
  let gsasl_random =
    F.foreign "gsasl_random" (ptr char @-> int @-> returning int)
      
  let gsasl_md5 =
    F.foreign "gsasl_md5"
      (string @-> int @-> ptr (ptr char) @-> returning int)
      
  let gsasl_hmac_md5 =
    F.foreign "gsasl_hmac_md5"
      (string @-> int @-> string @-> int @-> ptr (ptr char) @-> returning int)
      
  let gsasl_sha1 =
    F.foreign "gsasl_sha1"
      (string @-> int @-> ptr (ptr char) @-> returning int)
      
  let gsasl_hmac_sha1 =
    F.foreign "gsasl_hmac_sha1"
      (string @-> int @-> string @-> int @-> ptr (ptr char) @-> returning int)
end
