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

(** Bindings for GNU SASL library *)

type context
type session

type error =
  | OK
  (** Successful return code, guaranteed to be always 0. *)
  | NEEDS_MORE
  (** Mechanism expects another round-trip. *)
  | UNKNOWN_MECHANISM
  (** Application requested an unknown mechanism. *)
  | MECHANISM_CALLED_TOO_MANY_TIMES
  (** Application requested too many round trips from mechanism. *)
  | MALLOC_ERROR
  (** Memory allocation failed. *)
  | BASE64_ERROR
  (** Base64 encoding/decoding failed. *)
  | CRYPTO_ERROR
  (** Cryptographic error. *)
  | SASLPREP_ERROR
  (** Failed to prepare internationalized string. *)
  | MECHANISM_PARSE_ERROR
  (** Mechanism could not parse input. *)
  | AUTHENTICATION_ERROR
  (** Authentication has failed. *)
  | INTEGRITY_ERROR
  (** Application data integrity check failed. *)
  | NO_CLIENT_CODE
  (** Library was built with client functionality. *)
  | NO_SERVER_CODE
  (** Library was built with server functionality. *)
  | NO_CALLBACK
  (** Application did not provide a callback. *)
  | NO_ANONYMOUS_TOKEN
  (** Could not get required anonymous token. *)
  | NO_AUTHID
  (** Could not get required authentication identity (username). *)
  | NO_AUTHZID
  (** Could not get required authorization identity. *)
  | NO_PASSWORD
  (** Could not get required password. *)
  | NO_PASSCODE
  (** Could not get required SecurID PIN. *)
  | NO_PIN
  (** Could not get required SecurID PIN. *)
  | NO_SERVICE
  (** Could not get required service name. *)
  | NO_HOSTNAME
  (** Could not get required hostname. *)
  | NO_CB_TLS_UNIQUE
  (** Could not get required tls-unique CB. *)
  | NO_SAML20_IDP_IDENTIFIER
  (** Could not get required SAML IdP. *)
  | NO_SAML20_REDIRECT_URL
  (** Could not get required SAML redirect URL. *)
  | NO_OPENID20_REDIRECT_URL
  (** Could not get required OpenID redirect URL. *)
  | GSSAPI_RELEASE_BUFFER_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_IMPORT_NAME_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_INIT_SEC_CONTEXT_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_UNWRAP_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_WRAP_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_ACQUIRE_CRED_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_DISPLAY_NAME_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_UNSUPPORTED_PROTECTION_ERROR
  (** An unsupported quality-of-protection layer was requeted. *)
  | KERBEROS_V5_INIT_ERROR
  (** Init error in KERBEROS_V5. *)
  | KERBEROS_V5_INTERNAL_ERROR
  (** General error in KERBEROS_V5. *)
  | SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
  (** SecurID mechanism needs an additional passcode. *)
  | SECURID_SERVER_NEED_NEW_PIN
  (** SecurID mechanism needs an new PIN. *)
  | GSSAPI_ENCAPSULATE_TOKEN_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_DECAPSULATE_TOKEN_ERROR
  (**  GSS-API library call error. *)
  | GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_TEST_OID_SET_MEMBER_ERROR
  (** GSS-API library call error. *)
  | GSSAPI_RELEASE_OID_SET_ERROR
  (** GSS-API library call error. *)

exception Error of error * string * string

type property =
  (** Information properties, e.g., username. *)
  | AUTHID
  (** Authentication identity (username). *)
  | AUTHZID
  (** Authorization identity. *)
  | PASSWORD
  (** Password. *)
  | ANONYMOUS_TOKEN
  (** Anonymous identifier. *)
  | SERVICE
  (** Service name. *)
  | HOSTNAME
  (** Host name. *)
  | GSSAPI_DISPLAY_NAME
  (** GSS-API credential principal name. *)
  | PASSCODE
  (** SecurID passcode. *)
  | SUGGESTED_PIN
  (** SecurID suggested PIN. *)
  | PIN
  (** SecurID PIN. *)
  | REALM
  (** User realm. *)
  | DIGEST_MD5_HASHED_PASSWORD
  (** Pre-computed hashed DIGEST-MD5 password, to avoid storing passwords in
      the clear. *)
  | QOPS
  (** Set of quality-of-protection values. *)
  | QOP
  (** Quality-of-protection value. *)
  | SCRAM_ITER
  (** Number of iterations in password-to-key hashing. *)
  | SCRAM_SALT
  (** Salt for password-to-key hashing. *)
  | SCRAM_SALTED_PASSWORD
  (** Pre-computed salted SCRAM key, to avoid re-computation and storing
      passwords in the clear. *)
  | CB_TLS_UNIQUE
  (** Base64 encoded tls-unique channel binding. *)
  | SAML20_IDP_IDENTIFIER
  (** SAML20 user IdP URL. *)
  | SAML20_REDIRECT_URL
  (** SAML 2.0 URL to access in browser. *)
  | OPENID20_REDIRECT_URL
  (** OpenID 2.0 URL to access in browser. *)
  | OPENID20_OUTCOME_DATA
  (** OpenID 2.0 authentication outcome data. *)
  | SAML20_AUTHENTICATE_IN_BROWSER
  (** Request to perform SAML 2.0 authentication in browser. *)
  | OPENID20_AUTHENTICATE_IN_BROWSER
  (** Request to perform OpenID 2.0 authentication in browser. *)
  | VALIDATE_SIMPLE
  (** Request for simple validation. *)
  | VALIDATE_EXTERNAL
  (** Request for validation of EXTERNAL. *)
  | VALIDATE_ANONYMOUS
  (** Request for validation of ANONYMOUS. *)
  | VALIDATE_GSSAPI
  (** Request for validation of GSSAPI/GS2. *)
  | VALIDATE_SECURID
  (** Request for validation of SecurID. *)
  | VALIDATE_SAML20
  (** Request for validation of SAML20. *)
  | VALIDATE_OPENID20
  (** Request for validation of OpenID 2.0 login. *)

(** SASL mechanism name *)
type mech = string
(** The currently supported mechanism are:
    - ["EXTERNAL"]: Authentication via out of band information.
    - ["ANONYMOUS"]: Mechanism for anonymous access to resources.
    - ["PLAIN"]: Clear text username and password.
    - ["LOGIN"]: Non-standard clear text username and password.
    - ["CRAM-MD5"]: Challenge-Response Authentication Mechanism.
    - ["DIGEST-MD5"]: Digest Authentication.
    - ["SCRAM-SHA-1"]: SCRAM-SHA-1 authentication.
    - ["NTLM"]: Microsoft NTLM authentication.
    - ["SECURID"]: Authentication using tokens.
    - ["GSSAPI"]: GSSAPI (Kerberos 5) authentication.
    - ["GS2-KRB5"]: Improved GSSAPI (Kerberos 5) authentication.
    - ["SAML20"]: Authenticate using SAML 2.0 via a browser.
    - ["OPENID20"]: Authenticate using OpenID 2.0 via a browser.
    - ["KERBEROS_V5"]: Experimental KERBEROS_V5 authentication.

    Since some of these mechanisms depend on external libraries, only a subset
    might be available in your system.

    Different SASL mechanisms have different requirements on the application using
    it.  To handle these differences the library can use a callback function into
    your application in several different ways.  Some mechanisms, such as ["PLAIN"],
    are simple to explain and use.  The client callback queries the user for a
    username and password.  The server callback hands the username and password into
    any local policy deciding authentication system (such as /etc/passwd via PAM).

    See the
    {{:http://www.gnu.org/software/gsasl/manual/gsasl.html#Mechanisms}GNU SASL
    documentation} for the detailed requirements for each of the supported
    mechanisms. *)

(** The type of callbacks. *)
type callback = context -> session -> property -> [ `OK | `NO_CALLBACK ]
(** The callback will be used, via {!gsasl_callback}, by mechanisms to discover
    various parameters (such as username and passwords).  The callback function
    will be called with a {!gsasl_property} value indicating the requested
    behaviour.  For example, for [ANONYMOUS_TOKEN], the function is expected to
    invoke [gsasl_property_set ctx ANONYMOUS_TOKEN "token"] where ["token"] is
    the anonymous token the application wishes the SASL mechanism to use.

    Which properties you should handle is up to you. If you handle the request,
    you should return [`OK].  If you don't know how to respond to a certain
    property, simply return [`NO_CALLBACK]. The basic properties to support are
    authentication identity [AUTHID], authorization identity [AUTHZID], and
    password [PASSWORD].

    See {!gsasl_callback_set}. *)

val check_version : ?req_version:string -> unit -> string
(** [check_version ?rver] checks that the version of the library is at minimum
    the one given as a string in [?req_version] and return the actual version
    string of the library; raises [Failure "check_version"] if the condition is
    not met.  If [?req_version] is omitted, then no check is done and only the
    version string is returned. *)

val init : unit -> context
(** [init ()] initializes [libgsasl]. *)

val client_mechlist : context -> mech list
(** [client_mechlist ctx] returns a list of SASL mechanism names supported by
    the [libgsasl] client. *)

val server_mechlist : context -> mech list
(** [server_mechlist ctx] returns a list of SASL mechanism names supported by
    the [libgsasl] server. *)
    
val client_support_p : context -> mech -> bool
(** [client_support_p ctx mech] returns [true] if the [libgsasl] client supports
    the named mechanism, otherwise [false]. *)

val client_suggest_mechanism : context -> mech list -> mech option
(** [client_suggest_mechanism ctx mechlist] suggests which mechanism from
    [mechlist] to use. *)

val client_start : context -> mech -> session
(** [client_start ctx mech] initiates a client SASL authentication with
    mechanism [mech]. *)

val server_start : context -> mech -> session
(** [server_start ctx mech] initiates a server SASL authentication with
    mechanism [mech]. *)

val encode : session -> string -> string
(** [encode sctx s] will encode [s] according to the negotiated SASL mechanism
    in [sctx]. *)

val decode : session -> string -> string
(** [decode sctx s] will decode [s] according to the negotiated SASL mechanism
    in [sctx]. *)

val mechanism_name : session -> string option
(** [mechanism_name sctx] returns the name of the SASL mechanism used in the
    session [sctx] (or None if it is not known). *)
    
val property_set : session -> property -> string -> unit
(** [property_set ctx prop s] will make a copy of [s] and store it in the
    session handle [ctx] for the indicated property [prop]. *)

val property_get : session -> property -> string option
(** [property_get ctx prop] will retrieve the data stored in the
    session handle [ctx] for given property [prop], possibly invoking the
    application callback to get the value.

    This function will invoke the application callback, using {!callback}, when
    a property value is not known. *)

val step : session -> string -> [ `OK | `NEEDS_MORE ] * string
(** [step sctx data] performs one step of SASL authentication.  This reads
    [data] from the other end, processes it (potentially invoking callbacks to
    the application), and returns the data that should be sent to the server. *)

val step64 : session -> string -> [ `OK | `NEEDS_MORE ] * string
(** [step64 sctx data] is a simple wrapper around {!gsasl_step} that base64
    decodes the input and base64 encodes the output. *)

val callback_set : context -> callback -> unit
(** [callback_set ctx cb] will store the application provided callback
    [cb] in the library handle [ctx]. 

    If the callback raises any exception, the exception will be supressed and
    the value [`NO_CALLBACK] will be returned. *)
  
val callback : context -> session -> property -> [ `OK | `NO_CALLBACK ]
(** [callback ctx sctx prop] will invoke the application callback.  The [prop]
    value indicate what the callback is expected to do.  For example, for
    [ANONYMOUS_TOKEN], the function is expected to invoke [property_set sctx
    ANONYMOUS_TOKEN "token"] where ["token"] is the anonymous token the
    application wishes the SASL mechanism to use.

    This function returns whatever the application callback returns, or
    [`NO_CALLBACK] if no application was known. *)

val saslprep : ?allow_unassigned:bool -> string -> string
(** [saslprep allow s] will prepare the string [s] (assumed to be UTF8) using
    SASLprep.  This only works if [libgsasl] has been compiled with [libidn]
    support. *)

val base64_to : string -> string
(** [base64_to s] encodes data [s] as base64. *)

val base64_from : string -> string
(** [base64_from s] decode Base64 data [s]. *)

val nonce : int -> string
(** [nonce n] will return unpredictable data of size [n]. *)

val random : int -> string
(** [random n] will return cryptographically strong random data of size [n]. *)

val md5 : string -> string
(** [md5 s] will compute the MD5 hash of [s]. *)

val hmac_md5 : string -> string -> string
(** [hmac_md5 key s] will compute the HMAC-MD5 keyed checksum of [s]. *)

val sha1 : string -> string
(** [sha1 s] computes the SHA1 hash of [s]. *)

val hmac_sha1 : string -> string -> string
(** [hmac_sha1 key s] computes the HMAC-SHA1 keyed checksum of [s] with key
    [key]. *)
