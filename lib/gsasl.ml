(* The MIT License (MIT)

   Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE. *)

open Ctypes
open Foreign

type gsasl_t
type gsasl_session_t

let gsasl : gsasl_t structure typ = structure "gsasl"
let gsasl_session : gsasl_session_t structure typ = structure "gsasl_session"

let gsasl_null = from_voidp gsasl null
let gsasl_session_null = from_voidp gsasl_session null

type context = gsasl_t structure ptr

type session = gsasl_session_t structure ptr * context
(* we keep a reference to the corresponding [context] object so that the GC does
   not collect it while a session is still alive. *)

type error =
  | OK
  | NEEDS_MORE
  | UNKNOWN_MECHANISM
  | MECHANISM_CALLED_TOO_MANY_TIMES
  | MALLOC_ERROR
  | BASE64_ERROR
  | CRYPTO_ERROR
  | SASLPREP_ERROR
  | MECHANISM_PARSE_ERROR
  | AUTHENTICATION_ERROR
  | INTEGRITY_ERROR
  | NO_CLIENT_CODE
  | NO_SERVER_CODE
  | NO_CALLBACK
  | NO_ANONYMOUS_TOKEN
  | NO_AUTHID
  | NO_AUTHZID
  | NO_PASSWORD
  | NO_PASSCODE
  | NO_PIN
  | NO_SERVICE
  | NO_HOSTNAME
  | NO_CB_TLS_UNIQUE
  | NO_SAML20_IDP_IDENTIFIER
  | NO_SAML20_REDIRECT_URL
  | NO_OPENID20_REDIRECT_URL
  | GSSAPI_RELEASE_BUFFER_ERROR
  | GSSAPI_IMPORT_NAME_ERROR
  | GSSAPI_INIT_SEC_CONTEXT_ERROR
  | GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
  | GSSAPI_UNWRAP_ERROR
  | GSSAPI_WRAP_ERROR
  | GSSAPI_ACQUIRE_CRED_ERROR
  | GSSAPI_DISPLAY_NAME_ERROR
  | GSSAPI_UNSUPPORTED_PROTECTION_ERROR
  | KERBEROS_V5_INIT_ERROR
  | KERBEROS_V5_INTERNAL_ERROR
  | SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
  | SECURID_SERVER_NEED_NEW_PIN
  | GSSAPI_ENCAPSULATE_TOKEN_ERROR
  | GSSAPI_DECAPSULATE_TOKEN_ERROR
  | GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
  | GSSAPI_TEST_OID_SET_MEMBER_ERROR
  | GSSAPI_RELEASE_OID_SET_ERROR

exception Error of error * string * string

let error_of_int = function
  | 0 -> OK
  | 1 -> NEEDS_MORE
  | 2 -> UNKNOWN_MECHANISM
  | 3 -> MECHANISM_CALLED_TOO_MANY_TIMES
  | 7 -> MALLOC_ERROR
  | 8 -> BASE64_ERROR
  | 9 -> CRYPTO_ERROR
  | 29 -> SASLPREP_ERROR
  | 30 -> MECHANISM_PARSE_ERROR
  | 31 -> AUTHENTICATION_ERROR
  | 33 -> INTEGRITY_ERROR
  | 35 -> NO_CLIENT_CODE
  | 36 -> NO_SERVER_CODE
  | 51 -> NO_CALLBACK
  | 52 -> NO_ANONYMOUS_TOKEN
  | 53 -> NO_AUTHID
  | 54 -> NO_AUTHZID
  | 55 -> NO_PASSWORD
  | 56 -> NO_PASSCODE
  | 57 -> NO_PIN
  | 58 -> NO_SERVICE
  | 59 -> NO_HOSTNAME
  | 65 -> NO_CB_TLS_UNIQUE
  | 66 -> NO_SAML20_IDP_IDENTIFIER
  | 67 -> NO_SAML20_REDIRECT_URL
  | 68 -> NO_OPENID20_REDIRECT_URL
  | 37 -> GSSAPI_RELEASE_BUFFER_ERROR
  | 38 -> GSSAPI_IMPORT_NAME_ERROR
  | 39 -> GSSAPI_INIT_SEC_CONTEXT_ERROR
  | 40 -> GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
  | 41 -> GSSAPI_UNWRAP_ERROR
  | 42 -> GSSAPI_WRAP_ERROR
  | 43 -> GSSAPI_ACQUIRE_CRED_ERROR
  | 44 -> GSSAPI_DISPLAY_NAME_ERROR
  | 45 -> GSSAPI_UNSUPPORTED_PROTECTION_ERROR
  | 46 -> KERBEROS_V5_INIT_ERROR
  | 47 -> KERBEROS_V5_INTERNAL_ERROR
  | 48 -> SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
  | 49 -> SECURID_SERVER_NEED_NEW_PIN
  | 60 -> GSSAPI_ENCAPSULATE_TOKEN_ERROR
  | 61 -> GSSAPI_DECAPSULATE_TOKEN_ERROR
  | 62 -> GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
  | 63 -> GSSAPI_TEST_OID_SET_MEMBER_ERROR
  | 64 -> GSSAPI_RELEASE_OID_SET_ERROR
  | _ -> invalid_arg "error_of_int"

type property =
  | AUTHID
  | AUTHZID
  | PASSWORD
  | ANONYMOUS_TOKEN
  | SERVICE
  | HOSTNAME
  | GSSAPI_DISPLAY_NAME
  | PASSCODE
  | SUGGESTED_PIN
  | PIN
  | REALM
  | DIGEST_MD5_HASHED_PASSWORD
  | QOPS
  | QOP
  | SCRAM_ITER
  | SCRAM_SALT
  | SCRAM_SALTED_PASSWORD
  | CB_TLS_UNIQUE
  | SAML20_IDP_IDENTIFIER
  | SAML20_REDIRECT_URL
  | OPENID20_REDIRECT_URL
  | OPENID20_OUTCOME_DATA
  | SAML20_AUTHENTICATE_IN_BROWSER
  | OPENID20_AUTHENTICATE_IN_BROWSER
  | VALIDATE_SIMPLE
  | VALIDATE_EXTERNAL
  | VALIDATE_ANONYMOUS
  | VALIDATE_GSSAPI
  | VALIDATE_SECURID
  | VALIDATE_SAML20
  | VALIDATE_OPENID20

let int_of_property = function
  | AUTHID -> 1
  | AUTHZID -> 2
  | PASSWORD -> 3
  | ANONYMOUS_TOKEN -> 4
  | SERVICE -> 5
  | HOSTNAME -> 6
  | GSSAPI_DISPLAY_NAME -> 7
  | PASSCODE -> 8
  | SUGGESTED_PIN -> 9
  | PIN -> 10
  | REALM -> 11
  | DIGEST_MD5_HASHED_PASSWORD -> 12
  | QOPS -> 13
  | QOP -> 14
  | SCRAM_ITER -> 15
  | SCRAM_SALT -> 16
  | SCRAM_SALTED_PASSWORD -> 17
  | CB_TLS_UNIQUE -> 18
  | SAML20_IDP_IDENTIFIER -> 19
  | SAML20_REDIRECT_URL -> 20
  | OPENID20_REDIRECT_URL -> 21
  | OPENID20_OUTCOME_DATA -> 22
  | SAML20_AUTHENTICATE_IN_BROWSER -> 250
  | OPENID20_AUTHENTICATE_IN_BROWSER -> 251
  | VALIDATE_SIMPLE -> 500
  | VALIDATE_EXTERNAL -> 501
  | VALIDATE_ANONYMOUS -> 502
  | VALIDATE_GSSAPI -> 503
  | VALIDATE_SECURID -> 504
  | VALIDATE_SAML20 -> 505
  | VALIDATE_OPENID20 -> 506

let property_of_int = function
  | 1 -> AUTHID
  | 2 -> AUTHZID
  | 3 -> PASSWORD
  | 4 -> ANONYMOUS_TOKEN
  | 5 -> SERVICE
  | 6 -> HOSTNAME
  | 7 -> GSSAPI_DISPLAY_NAME
  | 8 -> PASSCODE
  | 9 -> SUGGESTED_PIN
  | 10 -> PIN
  | 11 -> REALM
  | 12 -> DIGEST_MD5_HASHED_PASSWORD
  | 13 -> QOPS
  | 14 -> QOP
  | 15 -> SCRAM_ITER
  | 16 -> SCRAM_SALT
  | 17 -> SCRAM_SALTED_PASSWORD
  | 18 -> CB_TLS_UNIQUE
  | 19 -> SAML20_IDP_IDENTIFIER
  | 20 -> SAML20_REDIRECT_URL
  | 21 -> OPENID20_REDIRECT_URL
  | 22 -> OPENID20_OUTCOME_DATA
  | 250 -> SAML20_AUTHENTICATE_IN_BROWSER
  | 251 -> OPENID20_AUTHENTICATE_IN_BROWSER
  | 500 -> VALIDATE_SIMPLE
  | 501 -> VALIDATE_EXTERNAL
  | 502 -> VALIDATE_ANONYMOUS
  | 503 -> VALIDATE_GSSAPI
  | 504 -> VALIDATE_SECURID
  | 505 -> VALIDATE_SAML20
  | 506 -> VALIDATE_OPENID20
  | _ -> invalid_arg "property_of_int"

type mech =
  string

let libgsasl =
  let names = ["libgsasl.so"; "libgsasl.dylib"] in
  let rec loop = function
    | [] ->
      failwith "libgsasl: could not load shared library"
    | x :: xs ->
      try Dl.dlopen ~filename:x ~flags:[]
      with _ -> loop xs
  in
  loop names

let _gsasl_check_version =
  foreign ~from:libgsasl "gsasl_check_version"
    (string_opt @-> returning string_opt)

let _gsasl_init =
  foreign ~from:libgsasl "gsasl_init" (ptr (ptr gsasl) @-> returning int)

let _gsasl_done =
  foreign ~from:libgsasl "gsasl_done" (ptr gsasl @-> returning void)

let _gsasl_strerror =
  foreign ~from:libgsasl "gsasl_strerror" (int @-> returning string)

let _gsasl_strerror_name =
  foreign ~from:libgsasl "gsasl_strerror_name" (int @-> returning string)

let _gsasl_client_mechlist =
  foreign ~from:libgsasl "gsasl_client_mechlist"
    (ptr gsasl @-> ptr (ptr char) @-> returning int)

let _gsasl_server_mechlist =
  foreign ~from:libgsasl "gsasl_server_mechlist"
    (ptr gsasl @-> ptr (ptr char) @-> returning int)

let _gsasl_client_support_p =
  foreign ~from:libgsasl "gsasl_client_support_p"
    (ptr gsasl @-> string @-> returning int)

let _gsasl_client_suggest_mechanism =
  foreign ~from:libgsasl "gsasl_client_suggest_mechanism"
    (ptr gsasl @-> string @-> returning string_opt)

let _gsasl_client_start =
  foreign ~from:libgsasl "gsasl_client_start"
    (ptr gsasl @-> string @-> ptr (ptr gsasl_session) @-> returning int)

let _gsasl_server_start =
  foreign ~from:libgsasl "gsasl_server_start"
    (ptr gsasl @-> string @-> ptr (ptr gsasl_session) @-> returning int)

let _gsasl_finish =
  foreign ~from:libgsasl "gsasl_finish"
    (ptr gsasl_session @-> returning void)

let _gsasl_encode =
  foreign ~from:libgsasl "gsasl_encode"
    (ptr gsasl_session @-> string @-> int @-> ptr (ptr char) @-> ptr int @-> returning int)

let _gsasl_decode =
  foreign ~from:libgsasl "gsasl_decode"
    (ptr gsasl_session @-> string @-> int @-> ptr (ptr char) @-> ptr int @-> returning int)

let _gsasl_mechanism_name =
  foreign ~from:libgsasl "gsasl_mechanism_name"
    (ptr gsasl_session @-> returning string_opt)

let _gsasl_property_set_raw =
  foreign ~from:libgsasl "gsasl_property_set_raw"
    (ptr gsasl_session @-> int @-> string @-> int @-> returning void)

let _gsasl_property_get =
  foreign ~from:libgsasl "gsasl_property_get"
    (ptr gsasl_session @-> int @-> returning string_opt)

let _gsasl_step =
  foreign ~from:libgsasl "gsasl_step"
    (ptr gsasl_session @-> string @-> int @-> ptr (ptr_opt char) @-> ptr int @-> returning int)

let _gsasl_step64 =
  foreign ~from:libgsasl "gsasl_step64"
    (ptr gsasl_session @-> string @-> ptr (ptr_opt char) @-> returning int)

let _gsasl_callback_set =
  foreign ~from:libgsasl "gsasl_callback_set"
    (ptr gsasl @-> funptr (ptr gsasl @-> ptr gsasl_session @-> int @-> returning int) @->
     returning void)

let _gsasl_callback =
  foreign ~from:libgsasl "gsasl_callback"
    (ptr gsasl @-> ptr gsasl_session @-> int @-> returning int)

let _gsasl_free =
  foreign ~from:libgsasl "gsasl_free"
    (ptr void @-> returning void)

let _gsasl_saslprep =
  foreign ~from:libgsasl "gsasl_saslprep"
    (string @-> int @-> ptr (ptr char) @-> ptr int @-> returning int)

let _gsasl_base64_to =
  foreign ~from:libgsasl "gsasl_base64_to"
    (string @-> int @-> ptr (ptr char) @-> ptr int @-> returning int)

let _gsasl_base64_from =
  foreign ~from:libgsasl "gsasl_base64_from"
    (string @-> int @-> ptr (ptr char) @-> ptr int @-> returning int)

let _gsasl_nonce =
  foreign ~from:libgsasl "gsasl_nonce"
    (ptr char @-> int @-> returning int)

let _gsasl_random =
  foreign ~from:libgsasl "gsasl_random"
    (ptr char @-> int @-> returning int)

let _gsasl_md5 =
  foreign ~from:libgsasl "gsasl_md5"
    (string @-> int @-> ptr (ptr char) @-> returning int)

let _gsasl_hmac_md5 =
  foreign ~from:libgsasl "gsasl_hmac_md5"
    (string @-> int @-> string @-> int @-> ptr (ptr char) @-> returning int)

let _gsasl_sha1 =
  foreign ~from:libgsasl "gsasl_sha1"
    (string @-> int @-> ptr (ptr char) @-> returning int)

let _gsasl_hmac_sha1 =
  foreign ~from:libgsasl "gsasl_hmac_sha1"
    (string @-> int @-> string @-> int @-> ptr (ptr char) @-> returning int)

let strerror n =
  _gsasl_strerror n

(* let strerror_name n = *)
(*   _gsasl_strerror_name n *)

let free x =
  _gsasl_free (to_voidp x)

let check_error fname n =
  if not (n = 0 || n = 1) then
    raise (Error (error_of_int n, fname, strerror n))

let check_version ?req_version () =
  match _gsasl_check_version req_version with
  | None -> failwith "check_version"
  | Some s -> s

let gsasl_done ctx =
  (* prerr_endline "gsasl_done"; *)
  _gsasl_done ctx

let init () =
  let ctx = allocate (ptr gsasl) gsasl_null in
  let n = _gsasl_init ctx in
  check_error "gsasl_init" n;
  let ctx = !@ ctx in
  Gc.finalise gsasl_done ctx;
  ctx

let split_list s =
  let get_next pos =
    try
      let next_pos = String.index_from s pos ' ' in
      let s = String.sub s pos (next_pos - pos) in
      Some (s, next_pos + 1)
    with
      | Not_found -> None
  in
  let rec add pos acc =
    match get_next pos with
      | None -> acc
      | Some (s, pos) -> add pos (s :: acc)
  in
  List.filter (fun s -> s <> "" ) (add 0 [])

let mechlist fname f ctx =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = f ctx out in
  check_error fname n;
  let out = !@ out in
  let s = coerce (ptr char) string out in
  free out;
  split_list s

let client_mechlist ctx =
  mechlist "gsasl_client_mechlist" _gsasl_client_mechlist ctx

let server_mechlist ctx =
  mechlist "gsasl_server_mechlist" _gsasl_server_mechlist ctx

let client_support_p ctx mech =
  let n = _gsasl_client_support_p ctx mech in
  n <> 0

let client_suggest_mechanism ctx mechlist =
  _gsasl_client_suggest_mechanism ctx (String.concat " " mechlist)

let gsasl_finish sctx =
  (* prerr_endline "gsasl_finish"; *)
  _gsasl_finish sctx

let string_of_buf p plen =
  let s = String.create plen in
  for i = 0 to plen-1 do
    String.unsafe_set s i (!@ (p +@ i))
  done;
  s

let encode (sctx, _) s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate int 0 in
  let n = _gsasl_encode sctx s (String.length s) out outlen in
  check_error "gsasl_encode" n;
  let out = !@ out in
  let outlen = !@ outlen in
  let s = string_of_buf out outlen in
  free out;
  s

let decode (sctx, _) s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate int 0 in
  let n = _gsasl_decode sctx s (String.length s) out outlen in
  check_error "gsasl_decode" n;
  let out = !@ out in
  let outlen = !@ outlen in
  let s = string_of_buf out outlen in
  free out;
  s

let start f fname ctx mech =
  let sctx = allocate (ptr gsasl_session) gsasl_session_null in
  let n = f ctx mech sctx in
  check_error fname n;
  let sctx = !@ sctx in
  Gc.finalise gsasl_finish sctx;
  (sctx, ctx)

let client_start ctx mech =
  start _gsasl_client_start "gsasl_client_start" ctx mech

let server_start ctx mech =
  start _gsasl_server_start "gsasl_server_start" ctx mech

let mechanism_name (sctx, _) =
  _gsasl_mechanism_name sctx

let property_set (sctx, _) prop data =
  _gsasl_property_set_raw sctx (int_of_property prop) data (String.length data)

let property_get (sctx, _) prop =
  _gsasl_property_get sctx (int_of_property prop)

let step (sctx, _) buf =
  let p = allocate (ptr_opt char) None in
  let plen = allocate int 0 in
  let n = _gsasl_step sctx buf (String.length buf) p plen in
  check_error "gsasl_step" n;
  let rc = match n with
    | 0 -> `OK
    | 1 -> `NEEDS_MORE
    | _ -> assert false
  in
  let plen = !@ plen in
  let p = !@ p in
  match p with
  | None ->
    rc, ""
  | Some p ->
    let s = string_of_buf p plen in
    free p;
    rc, s

let step64 (sctx, _) buf =
  let p = allocate (ptr_opt char) None in
  let n = _gsasl_step64 sctx buf p in
  check_error "gsasl_step64" n;
  let rc = match n with
    | 0 -> `OK
    | 1 -> `NEEDS_MORE
    | _ -> assert false
  in
  let p = !@ p in
  match p with
  | None ->
    rc, ""
  | Some p ->
    let s = coerce (ptr char) string p in
    free p;
    rc, s

type callback = context -> session -> property -> [ `OK | `NO_CALLBACK ]

let callback_set ctx callback =
  _gsasl_callback_set ctx
    (fun ctx sctx prop ->
       try match callback ctx (sctx, ctx) (property_of_int prop) with
       | `OK -> 0
       | `NO_CALLBACK -> 51
       with
       | _ -> 51)

let callback ctx (sctx, _) prop =
  let n = _gsasl_callback ctx sctx (int_of_property prop) in
  match n with
  | 0 -> `OK
  | 51 -> `NO_CALLBACK
  | _ -> assert false

let saslprep ?allow_unassigned:(allow_unassigned=false) s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = _gsasl_saslprep s (if allow_unassigned then 1 else 0) out (from_voidp int null) in
  check_error "gsasl_saslprep" n;
  let out = !@ out in
  let s = coerce (ptr char) string out in
  free out;
  s                           

let base64_to s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate int 0 in
  let n = _gsasl_base64_to s (String.length s) out outlen in
  check_error "gsasl_base64_to" n;
  let out = !@ out in
  let s = coerce (ptr char) string out in
  free out;
  s

let base64_from s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate int 0 in
  let n = _gsasl_base64_from s (String.length s) out outlen in
  check_error "gsasl_base64_from" n;
  let out = !@ out in
  let outlen = !@ outlen in
  let s = string_of_buf out outlen in
  free out;
  s

let nonce datalen =
  let out = allocate_n char datalen in
  let n = _gsasl_nonce out datalen in
  check_error "gsasl_nonce" n;
  string_of_buf out datalen

let random datalen =
  let out = allocate_n char datalen in
  let n = _gsasl_random out datalen in
  check_error "gsasl_random" n;
  string_of_buf out datalen

let md5 s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = _gsasl_md5 s (String.length s) out in
  check_error "gsasl_md5" n;
  let out = !@ out in
  let s = string_of_buf out 16 in
  free out;
  s

let hmac_md5 key s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = _gsasl_hmac_md5 key (String.length key) s (String.length s) out in
  check_error "gsasl_hmac_md5" n;
  let out = !@ out in
  let s = string_of_buf out 16 in
  free out;
  s

let sha1 s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = _gsasl_sha1 s (String.length s) out in
  check_error "gsasl_sha1" n;
  let out = !@ out in
  let s = string_of_buf out 20 in
  free out;
  s

let hmac_sha1 key s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = _gsasl_hmac_sha1 key (String.length key) s (String.length s) out in
  check_error "gsasl_hmac_sha1" n;
  let out = !@ out in
  let s = string_of_buf out 20 in
  free out;
  s
