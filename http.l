# adapted from the picolisp distribution
# (c) Software Lab. Alexander Burger

# CHANGES - cut out everything that isn't needed.
#
# - NEED "!" notation for calling lisp functions from url. That's a neat
#   feature.
#
# - NEED header parsing, and http response handling (_htHead, http)

# POST requests expect a single JSON.stringify'd string in the body of the
# request.
#
# A typical call from javascript would be something like,
#
#  fetch("some-url/!some-picolisp-function", {
#     method: "POST",
#     body: JSON.stringify({
#        token: "base64.encoded.jwt",
#        name: "erik",
#        password: "secretpassword"
#     })
#  }
#  .then( ... do things with the response ... );
#
# On the lisp side, 'http' will use json~decode to turn this string into an
# 'assoc' list. This list will be available for further processing in the 
# global variable '*Posted'. Use the 'posted' helper to get values from *Posted.
#
#  (let [Name  (posted "name")
#        Pass  (posted "password")
#        ... ]
#     ( ... do stuff ... ) )



# consider including "https://github.com/aw/picolisp-json" in this file?


# CHANGES BELOW

# *HPorts *Home *Gate *Host *Port *Port1 *Http1 *Chunked
# *Sock *Agent *ContL *ContLen "*HtSet"
# *Posted *Url
# *Referer

(mapc allow '(*Adr *Gate *Cipher *Host *ContL))

(zero *Http1)

### HTTP-Server ###
(de -server ()
   (server (format (opt)) (opt)) )

(de server (P H)
   (setq
      *Port P
      *Port1 (or (sys "NAME") P)
      *Home (cons H (chop H))
      P (port *Port) )
   (gc)
   (loop
      (setq *Sock (listen P))
      (NIL (fork) (close P))
      (close *Sock) )
   (task *Sock (http @))
   (http *Sock)
   (or *SesId (bye))
   (task *Sock
      (when (accept @)
         (task @ (http @)) ) ) )

(de retire (Min . Prg)
   (when (sys "PORT")
      (task -60000 60000  X (cons Min Min Prg)
         (cond
            (*Adr (off *Adr) (set X (cadr X)))
            ((kids) (set X (cadr X)))
            ((=0 (dec X)) (run (cddr X)) (bye)) ) )
      (forked) ) )

(de disallowed ()
   (and
      *Allow
      (not (idx *Allow *Url))
      (or
         (sub? ".." *Url)
         (nor
            (and *Tmp (pre? *Tmp *Url))
            (find pre? (cdr *Allow) (circ *Url)) ) ) ) )

(de notAllowed (X)
   (unless (= X "favicon.ico")
      (msg X " [" *Adr "] not allowed") ) )

# Handle HTTP-Transaction
(de http (*HtSock)
   (use (*Posted U L @X)
      (off *Posted *ContL *ContLen "*HtSet")
      (catch 'http
         (in *HtSock
            (case (till " " T)
               ("GET" (_htHead))
               ("POST"
                  (on *Posted)
                  (_htHead)
                  (if *ContLen
                     (setq *Posted (json~decode (ht:Pack (ht:Read @))))
                     (throw 'http) ) )
               (T
                  (and @ (out *HtSock (badRequest)))
                  (task (close *HtSock))
                  (off *HtSock)
                  (throw 'http) ) )
            (prog
               (setq
                  L (split U "?")
                  U (car L)
                  L (mapcan
                     '((A)
                        (cond
                           ((cdr (setq A (split A "=")))
                              (nil (_htSet (car A) (htArg (cadr A)))) )
                           ((tail '`(chop ".html") (car A))
                              (cons (pack (car A))) )
                           (T (cons (htArg (car A)))) ) )
                     (split (cadr L) "&") ) )
               (unless (setq *Url (ht:Pack U T))
                  (setq  *Url (car *Home)  U (cdr *Home)) )
               (out *HtSock
                  (cond
                     ((disallowed)
                        (notAllowed *Url)
                        (http404) )
                     ((= "!" (car U))
                        (apply (val (intern (ht:Pack (cdr U) T))) L) )
                     (T (httpEcho *Url "application/octet-stream" 1 T)) ) ) ) ) )
      (and *HtSock (=0 *Http1) (task (close *HtSock))) ) )

(de _htHead ()
   (unless
      (and
         (char)
         (= "/" (char))
         (prog (setq U (till " ")) (char))
         (= "HTTP/1" (till "." T))
         (char)
         (setq *Http1 (format (line T))) )
      (task (close *HtSock))
      (off *HtSock)
      (throw 'http) )
   (setq *Chunked (gt0 *Http1))
   (while
      (case (lowc (till " ^M^J" T))
         ("host:" (setq *Host (cdr (line))))
         ("referer:" (setq *Referer (cdr (line))))
         ("user-agent:" (setq *Agent (cdr (line))))
         ("content-length:" (setq *ContLen (format (cdr (line)))))
         ("content-type:"
            (if (= " multipart/form-data; boundary" (lowc (till "=" T)))
               (setq
                  *MPartLim (append '(- -) (cdr (line)))
                  *MPartEnd (append *MPartLim '(- -)) )
               (line) ) )
         ("x-pil:"
            (char)
            (when (till "=")
               (_htSet @ (ht:Pack (cdr (line)) T))
               T ) )
         (T (if (eol) (char) (line T))) ) )
   (unless *Gate
      (and (member ":" *Host) (con (prior @ *Host))) ) )

(de _htSet (L Val)
   (let "Var" (intern (ht:Pack (car (setq L (split L ":"))) T))
      (cond
         ((and *Allow (not (idx *Allow "Var")))
            (notAllowed "Var")
            (throw 'http) )
         ((cadr L)
            (let? N (format (car (setq L (split @ "."))))
               (case (caadr L)
                  ("x" (setq Val (cons (format Val))))
                  ("y" (setq Val (cons NIL (format Val)))) )
               (nond
                  ((memq "Var" "*HtSet")
                     (push '"*HtSet" "Var")
                     (set "Var" (cons (cons N Val)))
                     Val )
                  ((assoc N (val "Var"))
                     (queue "Var" (cons N Val))
                     Val )
                  (NIL
                     (let X @
                        (cond
                           ((nand (cadr L) (cdr X)) (con X Val))
                           ((car Val) (set (cdr X) @))
                           (T (con (cdr X) (cdr Val))) ) ) ) ) ) )
         (T
            (if (= "*" (caar L))
               (set "Var" Val)
               (put "Var" 'http Val) ) ) ) ) )

(de htArg (Lst)
   (case (car Lst)
      ("$" (intern (ht:Pack (cdr Lst) T)))
      ("+" (format (cdr Lst)))
      ("-" (extern (ht:Pack (cdr Lst) T)))
      ("_" (mapcar htArg (split (cdr Lst) "_")))
      (T (ht:Pack Lst T)) ) )

# Http Transfer Header
(de http1 (Typ Upd File Att)
   (prinl "HTTP/1." *Http1 " 200 OK^M")
   (prinl "Server: PicoLisp^M")
   (prin "Date: ")
   (httpDate (date T) (time T))
   (when Upd
      (prinl "Cache-Control: max-age=" Upd "^M")
      (when (=0 Upd)
         (prinl "Cache-Control: private, no-store, no-cache^M") ) )
   (prinl "Content-Type: " (or Typ "text/html; charset=utf-8") "^M")
   (when File
      (prinl
         "Content-Disposition: "
         (if Att "attachment" "inline")
         "; filename=\"" File "\"^M" ) ) )

(de respond (S)
   (http1 "application/octet-stream" 0)
   (prinl "Content-Length: " (size S) "^M^J^M")
   (prin S) )

(de httpHead (Typ Upd File Att)
   (http1 Typ Upd File Att)
   (and *Chunked (prinl "Transfer-Encoding: chunked^M"))
   (prinl "^M") )

(de httpDate (Dat Tim)
   (let D (date Dat)
      (prinl
         (day Dat *Day) ", "
         (pad 2 (caddr D)) " "
         (get *Mon (cadr D)) " "
         (car D) " "
         (tim$ Tim T) " GMT^M" ) ) )

# Http Echo
(de httpEcho (File Typ Upd Att)
   (and *Tmp (pre? *Tmp File) (one Upd))
   (ifn (info File)
      (http404)
      (let I @
         (http1 (or Typ (mimetype File)) Upd (stem (chop File) "/") Att)
         (prinl "Content-Length: " (car I) "^M")
         (prin "Last-Modified: ")
         (httpDate (cadr I) (cddr I))
         (prinl "^M")
         (in File (echo)) ) ) )

(de *Mimes
   (`(chop "html") "text/html; charset=utf-8")
   (`(chop "svg") "image/svg+xml; charset=utf-8")
   (`(chop "au") "audio/basic" 3600)
   (`(chop "wav") "audio/x-wav" 3600)
   (`(chop "mp3") "audio/x-mpeg" 3600)
   (`(chop "gif") "image/gif" 3600)
   (`(chop "tif") "image/tiff" 3600)
   (`(chop "tiff") "image/tiff" 3600)
   (`(chop "bmp") "image/bmp" 86400)
   (`(chop "png") "image/png" 86400)
   (`(chop "jpg") "image/jpeg" 3600)
   (`(chop "jpeg") "image/jpeg" 3600)
   (`(chop "txt") "text/octet-stream" 1 T)
   (`(chop "csv") "text/csv; charset=utf-8" 1 T)
   (`(chop "css") "text/css" 86400)
   (`(chop "js") "application/x-javascript" 86400)
   (`(chop "ps") "application/postscript" 1)
   (`(chop "pdf") "application/pdf" 1)
   (`(chop "zip") "application/zip" 1)
   (`(chop "jar") "application/java-archive" 86400) )

(de mime (S . @)
   (let L (chop S)
      (if (assoc L *Mimes)
         (con @ (rest))
         (push '*Mimes (cons L (rest))) ) ) )

(de mimetype (File Typ)
   (in (list 'file "-b" (if Typ "--mime-type" "--mime") File)
      (line T) ) )

(de httpStat (N X . @)
   (let B (fin X)
      (if (pair X)
         (setq X (car X))
         (setq B (pack "<H1>" B "</H1>")) )
      (prinl "HTTP/1." *Http1 " " N " " X "^M")
      (prinl "Server: PicoLisp^M")
      (while (args)
         (prinl (next) "^M") )
      (prinl "Content-Type: text/html^M")
      (httpCookies)
      (prinl "Content-Length: " (+ 59 (length N) (length X) (length B)) "^M")
      (prinl "^M")
      (prinl "<HTML>")
      (prinl "<HEAD><TITLE>" N " " X "</TITLE></HEAD>")
      (prinl "<BODY>" B "</BODY>")
      (prinl "</HTML>") ) )

#simple HTTP responses
(de noContent ()
   (prinl "HTTP/1.0 204 No Content^M")
   (prinl "Access-Control-Allow-Origin: *^M")
   (prinl "^M") )

(de badRequest ()
   (prinl "HTTP/1.0 400 Bad Request^M")
   (prinl "Access-Control-Allow-Origin: *^M")
   (prinl "^M") )

(de forbidden ()
   (prinl "HTTP/1.0 403 Forbidden^M")
   (prinl "Access-Control-Allow-Origin: *^M")
   (prinl "^M") )

(de http404 ()
   (httpStat 404 "Not Found") )

# json utils - requires "https://github.com/aw/picolisp-json"
(de respondJson (Lst)
   (let Json (json~encode Lst)
      (http1 "application/json" 0)
      (prinl "Access-Control-Allow-Origin: *^M")
      (prinl "Content-Length: " (size Json) "^M^J^M")
      (prin Json) ) )

# get val from *Posted (see above)
#
# USAGE - call in API fn (e.g. "!doSomething")
#
#  (de doSomething ()
#     (let Token (posted "token")
#        (doSomethingWithToken)
#        ... ) )
#
(de posted (Key)
   (cdr (assoc Key *Posted)) )

# get json val from list
(de getJson (Key Lst)
   (cdr (assoc Key Lst)) )

# by this convention, server-side errors are returned as,
# 
#    { error: "Something went wrong" }
#
# to be displayed on the client.
(de respondJsonError (Str)
   (respondJson
      (list
         (cons "error"
            Str ) ) ) )

# vi:et:ts=3:sw=3
