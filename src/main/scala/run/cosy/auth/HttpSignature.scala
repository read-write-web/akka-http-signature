package run.cosy.auth

import java.io.UnsupportedEncodingException
import java.net.MalformedURLException
import java.security.{NoSuchAlgorithmException, PrivateKey, PublicKey, Signature}
import java.util.Base64

import akka.http.scaladsl.model.headers._
import akka.http.scaladsl.model.{HttpHeader, HttpRequest, Uri}
import run.cosy.auth.HttpSignature.Algorithm
import run.cosy.auth.HttpSignature.Server.SigFail

import scala.util.{Failure, Success, Try}


sealed trait AuthZException extends Exception
case class MissingACLException(resource: Uri) extends AuthZException
//case class NoAuthorization(subject: Subject, on: Uri, mode: Method.Value) extends AuthZException

// Authentiction Exceptions
sealed trait AuthNException extends Exception
case class ClientAuthNDisabled(msg: String, e: Option[Throwable]=None) extends AuthNException
case class OtherAuthNException(e: Throwable) extends AuthNException


trait HttpAuthNException extends AuthNException
case class SignatureRequestException(msg: String) extends HttpAuthNException

trait SignatureAuthNException extends HttpAuthNException
//todo: the exception here should be one returned by rww.execute
case class FetchException(sigInfo: SigInfo, e: Throwable) extends SignatureAuthNException
case class SignatureVerificationException(msg: String, sigInfo: SignedInfo) extends SignatureAuthNException
//case class KeyIdException[Rdf<:RDF](msg: String, sigInfo: SigInfo, pg: PointedGraph[Rdf]) extends SignatureAuthNException



object HttpSignature {
   
   case class Algorithm(specName: String, javaName: String) {
      def signature: Signature = Signature.getInstance(javaName)
   }
   
   object `rsa-sha256` extends Algorithm("rsa-sha256","SHA256withRSA")
   
   object Algorithm {
      val algorithMap: Map[String, Algorithm] = Seq[Algorithm](`rsa-sha256`).map(a=>(a.specName,a)).toMap
      
      def apply(specname: String): Try[Algorithm] = algorithMap.get(specname)
       .fold[Try[Algorithm]](SigFail(s"algorithm '$specname' not known"))(Success(_))
   }

  /**
    * This function is used to build the `signature string` from the request.
    * This is used by both the client and the server:
    * <ul>
    * <li> the client, uses it to generate the signature that will be added to the `Authorization` or `Signature` header
    * <li> the server uses it to verifty the signature received in the `Authorization` or `Signature` header
    * </ul>
    *
    * @param req     the  HttpRequest from which the signature text is built
    * @param headers the lowercase list of headers that need to be used to build the signature
    * @return a Try of the string to be signed
    */
  def buildSignatureText(req: HttpRequest, headers: List[String]=List()): Try[String] = try {
    Success(headers.map {
      case rt@"(request-target)" =>
        rt + ": " + req.method.value.toLowerCase + " " + req.uri.path +
          req.uri.rawQueryString.map("?" + _).getOrElse("")
      case ct@"content-type" => ct + ": " + req.entity.contentType.toString
      case cl@"content-length" => cl + ": " + req.entity.contentLengthOption.getOrElse {
         throw SignatureRequestException("no content-length for this header")
      }
      case name =>
        val values = req.headers.collect{ case HttpHeader(`name`,value) => value}
        if (values.isEmpty)
          throw SignatureRequestException(s"found no header for $name in request")
        else name + ": " + values.mkString(",")
    }.mkString("\n")
    )
  } catch {
    //for discussion on this type of control flow see:
    //   http://stackoverflow.com/questions/2742719/how-do-i-break-out-of-a-loop-in-scala
    //   http://stackoverflow.com/questions/12892701/abort-early-in-a-fold
    //   http://www.tzavellas.com/techblog/2010/09/20/catching-throwable-in-scala/
    case e: SignatureRequestException => Failure(e)
  }



  object Server {
    def SigVFail(errorMsg: String, sigInfo: SignedInfo) =
      Failure(SignatureVerificationException(errorMsg, sigInfo))

    def SigFail(errorMsg: String) = Failure(SignatureRequestException(errorMsg))


    /**
      * @param authorization the Authorization header already extracted from the `req` header.
      * @param req the http request which was signed with the authorization
      * @return a SigInfo if possible
      * //todo: use the akka Uri class
      */
    def parseSignatureInfo(authorization: Authorization, req: HttpRequest): Try[SignedInfo] = {
      val params = authorization.credentials.params
      for {
        keyUrl <- params.get("keyId")
          .fold[Try[Uri]](SigFail("no keyId attribute")) { id =>
          Try(Uri(id)) recoverWith {
            case e: MalformedURLException => SigFail("could not transform keyId to URL")
          }
        }
        algo <- params.get("algorithm").fold[Try[Algorithm]](SigFail("algorithm used in signature must be specified")){
           Algorithm(_)
        }
        signature <- params.get("signature")
          .fold[Try[Array[Byte]]](SigFail("no signature was sent!")) { sig =>
          Try(Base64.getDecoder.decode(sig)).recoverWith {
            case e: IllegalArgumentException => SigFail("signature is not a base64 encoding")
          }
        }
        headers = params.get("headers").map{hdrs =>
             hdrs.split("""\s+""").toList  //<- what if this one is empty? Does that always lead to an error?
           }.getOrElse(List("date"))
        sigText <- buildSignatureText(req,headers)

      } yield new SignedInfo(new SigInfo(headers, algo, keyUrl, sigText), signature)
    }

  }

  object Client {
     /**
       * todo: the realm is not used.
       * find the list of headers recommended by the server to build up the signature text
       *
       * @param wwwAuthHeader the parsed WWW-Authenticate header
       * @return the list of headers recommended by the server
       */
     def signatureHeaders(wwwAuthHeader: `WWW-Authenticate`): Option[List[String]] =
        wwwAuthHeader.challenges.collectFirst {
           case HttpChallenge("Signature", realm, params) =>
              params.get("headers").map(_.split("""\s+""")).getOrElse(Array("date")).toList
        }
     
  }
   
   case class Client(keyId: Uri, privKey: PrivateKey) {
   
      //todo: how much of this info is collectable from the the WWW-Authentictate, ie, just passed on from the server?
      //   for each one see, as that may determine how strongly the arguments should be typed
      def authorize(
       req: HttpRequest,
       signatureHeaders: List[String]=List("date"),
       algorithm: Algorithm=`rsa-sha256`
      ): Try[Authorization] = {
         HttpSignature.buildSignatureText(req, signatureHeaders).flatMap { sigtxt =>
            val si = new SigInfo(signatureHeaders, algorithm = algorithm , keyId, sigtxt)
            si.sign(privKey).map(_.makeAuthorization)
         }
      }
   }
   
}

 class SigInfo(
  val headers: List[String],  //the headers used to make the signature text
  val algorithm: Algorithm,  //the algorithm to be used in the signature, and verification
  val keyId: Uri, //the id of the key that will sign
  val sigText: String,  //the text to be signed
) {
    
  def sign(privKey: PrivateKey): Try[SignedInfo]  =
    signBytes(privKey).map(new SignedInfo(this,_))

  /**
    *
    * @param privkey the private key to sign the text
    * @return a Try of the Signed Bytes (which then needs to be hex encoded)
    *         The Try can capture
    *         - java.security.NoSuchAlgorithmException
    *         - java.security.InvalidKeyException
    *         - java.security.SignatureException
    */
  private def signBytes(privkey: PrivateKey): Try[Array[Byte]] = Try {
    val sig = algorithm.signature
    sig.initSign(privkey)
    sig.update(sigText.getBytes("US-ASCII"))
    sig.sign()
  }

}


class SignedInfo(
  val sigInfo: SigInfo,
  private val signature: Array[Byte]
) {
  import HttpSignature.Server.SigVFail

  def verify(pubKey: PublicKey): Try[Uri] = {
    try {
      val sig = sigInfo.algorithm.signature
      sig.initVerify(pubKey)
      sig.update(sigInfo.sigText.getBytes("US-ASCII")) //should be ascii only
      if (sig.verify(signature)) Success(sigInfo.keyId)
      else SigVFail("could not cryptographically verify signature", this)
    } catch {
      case nsa: NoSuchAlgorithmException => SigVFail("could not find implementation for " +
        sigInfo.algorithm, this)
      case ue: UnsupportedEncodingException => Failure(new Throwable("could not find US-ASCII Encoding!",ue))
      case iae: IllegalArgumentException => SigVFail("could not decode base64 encoded signature", this)
    }
  }

  lazy val encodedSig: String = Base64.getEncoder.encodeToString(signature)

  def makeAuthorization: Authorization = {
    val atvals: Seq[(String,String)] = Seq("keyId" -> sigInfo.keyId.toString, "algorithm" -> sigInfo.algorithm.specName,
      "headers" -> sigInfo.headers.mkString(" "),
      "signature" -> encodedSig )
    Authorization(GenericHttpCredentials("Signature", Map(atvals:_*)))
  }

}



