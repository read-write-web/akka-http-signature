package run.cosy.auth

import java.io.StringReader
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.{RSAPrivateKeySpec, RSAPublicKeySpec}
import java.util.Base64

import akka.http.scaladsl.model.HttpEntity.Strict
import akka.http.scaladsl.model.MediaTypes._
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.{Date, _}
import akka.util.ByteString
import org.bouncycastle.asn1.{ASN1InputStream, pkcs}
import org.bouncycastle.util.io.pem.PemReader
import org.scalatest.Matchers._
import org.scalatest._

import scala.collection.immutable

class HttpSignatureSpecTest  extends FreeSpec {
  
  val rsaKeyFactory = KeyFactory.getInstance("RSA")
  
  //these two keys are taken from the spec
  val rsaPublicKeyMime = """
      |MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
      |6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
      |Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
      |oYi+1hqp1fIekaxsyQIDAQAB""".stripMargin.trim.lines.mkString("\r\n")
  
  val rsaPrivateKeyMime = """
      |MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
      |NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
      |UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
      |AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
      |QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
      |kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
      |f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
      |412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
      |mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
      |kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
      |gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
      |G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
      |7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==""".stripMargin.trim.lines.mkString("\r\n")
  
  val rsaPubKey = {
    //cannot do this without bouncy castle
    //https://stackoverflow.com/questions/4032985/how-do-we-convert-a-string-from-pem-to-der-format
    val pemReader = new PemReader(new StringReader(rsaPublicKeyMime))
    pemReader.readPemObject().asInstanceOf[RSAPublicKey]
// this should work too:
//    val keyBytes = Base64.getMimeDecoder.decode(rsaPublicKeyMime)
//    val pStruct = pkcs.RSAPublicKey.getInstance(new ASN1InputStream(keyBytes).readObject)
//    val spec = new RSAPublicKeySpec(pStruct.getModulus, pStruct.getPublicExponent)
//    rsaKeyFactory.generatePublic(spec)
  }
  
  val rsaPrivateKey = {
    val keyBytes = Base64.getMimeDecoder.decode(rsaPrivateKeyMime)
    val pStruct = pkcs.RSAPrivateKey.getInstance(new ASN1InputStream(keyBytes).readObject)
    val spec = new RSAPrivateKeySpec(pStruct.getModulus, pStruct.getPrivateExponent)
    rsaKeyFactory.generatePrivate(spec)
  }
  
  
  "testing examples in HTTP Signature spec" - {
    //https://w3c-dvcg.github.io/http-signatures/#headers

//   POST /foo HTTP/1.1
//   Host: example.org
//   Date: Tue, 07 Jun 2014 20:51:35 GMT
//   Content-Type: application/json
//   Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
//   Content-Length: 18
//
//   {"hello": "world"}"""

    val request = HttpRequest(
      HttpMethods.POST,Uri("/foo"),
      immutable.Seq(
        Host("example.org"),
        Date(DateTime(2014,6,7,20,51,35)),
        RawHeader("Digest","SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")
      ),
      entity = Strict(ContentType(`application/json`),ByteString("""{"hello": "world"}"""))
    )
  
    //https://w3c-dvcg.github.io/http-signatures/#auth-isa
    "Initiating Signature Authorization" - {

      // header is captured by code below, but it's not easy to build request from a string
//      """
//        |HTTP/1.1 401 Unauthorized
//        |Date: Thu, 08 Jun 2014 18:32:30 GMT
//        |Content-Length: 1234
//        |Content-Type: text/html
//        |WWW-Authenticate: Signature realm="Example",headers="(request-target) date"
//        |""".stripMargin.trim

      val serverResponse = HttpResponse(headers=immutable.Seq(
        Date(DateTime(2014,6,8,18,32,30)),
        `Content-Length`(1234),
        `Content-Type`(`text/html`.toContentTypeWithMissingCharset),
        `WWW-Authenticate`(HttpChallenge("Signature","Example",Map("headers"->"(request-target) date")))
      ))

      val serverRequiredHeaders = List("(request-target)", "date")
      
      "should extract the list of headers to be signed as requested by the server" in {
        val headersForSig = HttpSignature.Client.signatureHeaders(serverResponse.header[`WWW-Authenticate`].get).get
        serverRequiredHeaders should be(headersForSig)
      }

      val expectedToBeSignedTxt = """
           |(request-target): post /foo
           |date: Sat, 07 Jun 2014 20:51:35 GMT
           """.stripMargin.trim
  
      "for the given request and needed headers the signature text should be" in {
        val toSignText = HttpSignature.buildSignatureText(request,serverRequiredHeaders)
        expectedToBeSignedTxt should be(toSignText.get)
      }
      
      val moreHeaders = serverRequiredHeaders:::List("content-type")
      val expctToBeSignedTxt2 = """
          |(request-target): post /foo
          |date: Sat, 07 Jun 2014 20:51:35 GMT
          |content-type: application/json""".stripMargin.trim
      
      "for the extra headers content-type header the signature text should be" in {
        val toSignText = HttpSignature.buildSignatureText(request,moreHeaders)
        expctToBeSignedTxt2 should be(toSignText.get)
      }
  
      val evenMoreHeaders = moreHeaders:::List("content-length")
      val expctToBeSignedTxt3 = """
          |(request-target): post /foo
          |date: Sat, 07 Jun 2014 20:51:35 GMT
          |content-type: application/json
          |content-length: 18""".stripMargin.trim
  
      "for the extra content-length header the signature text should be" in {
        val toSignText = HttpSignature.buildSignatureText(request,evenMoreHeaders)
        expctToBeSignedTxt3 should be(toSignText.get)
      }
  
    }
  
    "signature tests" - {
      
      val signer = HttpSignature.Client(Uri("Test"),rsaPrivateKey)
      
      "default test https://w3c-dvcg.github.io/http-signatures/#rfc.section.C.1" in {
        val defaultReq = HttpRequest(uri=Uri("/foo"),
          headers=immutable.Seq(
            Date(DateTime(2014,1,5,21,31,40)),
          )
        )
        val resultSig = """
            |ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htH
            |FYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+
            |xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=""".trim.stripMargin
        val authTry = signer.authorize(defaultReq)
        authTry.isSuccess should be(true)
        
        println(defaultReq)
        println(resultSig)
        println(authTry)
      }
      
    }

  }

}
