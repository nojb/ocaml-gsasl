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
open Gsasl_bindings

module B = Bindings (Gsasl_generated)

type context = {
  ctx : gsasl_t structure ptr;
  mutable gc_cb :
    (gsasl_t structure ptr -> gsasl_session_t structure ptr -> int -> int) option
}

type session = {
  sctx : gsasl_session_t structure ptr;
  gc_ctx : context
}
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

(* let libgsasl = *)
(*   let names = ["libgsasl.so"; "libgsasl.dylib"] in *)
(*   let rec loop = function *)
(*     | [] -> *)
(*       failwith "libgsasl: could not load shared library" *)
(*     | x :: xs -> *)
(*       try Dl.dlopen ~filename:x ~flags:[] *)
(*       with _ -> loop xs *)
(*   in *)
(*   loop names *)

(* let foreign fname fn = *)
(*   foreign (\* ~from:libgsasl *\) fname fn *)

let strerror n =
  B.gsasl_strerror n

let free x =
  B.gsasl_free (to_voidp x)

let check_error fname n =
  if not (n = 0 || n = 1) then
    raise (Error (error_of_int n, fname, strerror n))

let check_version ?req_version () =
  match B.gsasl_check_version req_version with
  | None -> failwith "check_version"
  | Some s -> s

let init () =
  let ctx = allocate (ptr gsasl) gsasl_null in
  let n = B.gsasl_init ctx in
  check_error "gsasl_init" n;
  let ctx = !@ ctx in
  Gc.finalise B.gsasl_done ctx;
  {ctx; gc_cb = None}

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

let mechlist fname f {ctx} =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = f ctx out in
  check_error fname n;
  let out = !@ out in
  let s = coerce (ptr char) string out in
  free out;
  split_list s

let client_mechlist ctx =
  mechlist "gsasl_client_mechlist" B.gsasl_client_mechlist ctx

let server_mechlist ctx =
  mechlist "gsasl_server_mechlist" B.gsasl_server_mechlist ctx

let client_support_p {ctx} mech =
  let n = B.gsasl_client_support_p ctx mech in
  n <> 0

let client_suggest_mechanism {ctx} mechlist =
  B.gsasl_client_suggest_mechanism ctx (String.concat " " mechlist)

let encode {sctx} s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate size_t Unsigned.Size_t.zero in
  let n = B.gsasl_encode sctx s (String.length s) out outlen in
  check_error "gsasl_encode" n;
  let out = !@ out in
  let outlen = Unsigned.Size_t.to_int (!@ outlen) in
  let s = string_from_ptr out outlen in
  free out;
  s

let decode {sctx} s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate size_t Unsigned.Size_t.zero in
  let n = B.gsasl_decode sctx s (String.length s) out outlen in
  check_error "gsasl_decode" n;
  let out = !@ out in
  let outlen = Unsigned.Size_t.to_int (!@ outlen) in
  let s = string_from_ptr out outlen in
  free out;
  s

let start f fname ctx mech =
  let sctx = allocate (ptr gsasl_session) gsasl_session_null in
  let n = f ctx.ctx mech sctx in
  check_error fname n;
  let sctx = !@ sctx in
  Gc.finalise B.gsasl_finish sctx;
  {sctx; gc_ctx = ctx}

let client_start ctx mech =
  start B.gsasl_client_start "gsasl_client_start" ctx mech

let server_start ctx mech =
  start B.gsasl_server_start "gsasl_server_start" ctx mech

let mechanism_name {sctx} =
  B.gsasl_mechanism_name sctx

let property_set {sctx} prop data =
  B.gsasl_property_set_raw sctx (int_of_property prop) data (String.length data)

let property_get {sctx} prop =
  B.gsasl_property_get sctx (int_of_property prop)

let step {sctx} buf =
  let p = allocate (ptr_opt char) None in
  let plen = allocate size_t Unsigned.Size_t.zero in
  let n = B.gsasl_step sctx buf (String.length buf) p plen in
  check_error "gsasl_step" n;
  let rc = match n with
    | 0 -> `OK
    | 1 -> `NEEDS_MORE
    | _ -> assert false
  in
  let plen = Unsigned.Size_t.to_int (!@ plen) in
  let p = !@ p in
  match p with
  | None -> rc, ""
  | Some p ->
    let s = string_from_ptr p plen in
    free p;
    rc, s

let step64 {sctx} buf =
  let p = allocate (ptr_opt char) None in
  let n = B.gsasl_step64 sctx buf p in
  check_error "gsasl_step64" n;
  let rc = match n with
    | 0 -> `OK
    | 1 -> `NEEDS_MORE
    | _ -> assert false
  in
  let p = !@ p in
  match p with
  | None -> rc, ""
  | Some p ->
    let s = coerce (ptr char) string p in
    free p;
    rc, s

type callback = property -> [ `OK | `NO_CALLBACK ]

let callback_set ctx callback =
  let cb _ _ prop =
    try match callback (property_of_int prop) with
      | `OK -> 0
      | `NO_CALLBACK -> 51
    with
    | _ -> 51
  in
  ctx.gc_cb <- Some cb;
  B.gsasl_callback_set ctx.ctx cb

let saslprep ?(allow_unassigned=false) s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = B.gsasl_saslprep s (if allow_unassigned then 1 else 0) out (from_voidp int null) in
  check_error "gsasl_saslprep" n;
  let out = !@ out in
  let s = coerce (ptr char) string out in
  free out;
  s                           

let base64_to s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate size_t Unsigned.Size_t.zero in
  let n = B.gsasl_base64_to s (String.length s) out outlen in
  check_error "gsasl_base64_to" n;
  let out = !@ out in
  let outlen = Unsigned.Size_t.to_int (!@ outlen) in
  let s = string_from_ptr out outlen in
  free out;
  s

let base64_from s =
  let out = allocate (ptr char) (from_voidp char null) in
  let outlen = allocate size_t Unsigned.Size_t.zero in
  let n = B.gsasl_base64_from s (String.length s) out outlen in
  check_error "gsasl_base64_from" n;
  let out = !@ out in
  let outlen = Unsigned.Size_t.to_int (!@ outlen) in
  let s = string_from_ptr out outlen in
  free out;
  s

let genbytes f fname datalen =
  let out = allocate_n char datalen in
  let n = f out datalen in
  check_error fname n;
  string_from_ptr out datalen  

let nonce datalen =
  genbytes B.gsasl_nonce "gsasl_nonce" datalen

let random datalen =
  genbytes B.gsasl_random "gsasl_random" datalen

let hash f fname len s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = f s (String.length s) out in
  check_error fname n;
  let out = !@ out in
  let s = string_from_ptr out len in
  free out;
  s

let hmac_hash f fname len key s =
  let out = allocate (ptr char) (from_voidp char null) in
  let n = f key (String.length key) s (String.length s) out in
  check_error fname n;
  let out = !@ out in
  let s = string_from_ptr out len in
  free out;
  s

let md5 s =
  hash B.gsasl_md5 "gsasl_md5" 16 s

let hmac_md5 key s =
  hmac_hash B.gsasl_hmac_md5 "gsasl_hmac_md5" 16 key s

let sha1 s =
  hash B.gsasl_sha1 "gsasl_sha1" 20 s

let hmac_sha1 key s =
  hmac_hash B.gsasl_hmac_sha1 "gsasl_hmac_sha1" 20 key s
