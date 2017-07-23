package run.cosy.auth

import run.cosy.auth.HttpSignature.{Client, Server}

import akka.http.scaladsl.model.HttpEntity.Strict
import akka.http.scaladsl.model.MediaTypes._
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.{Date, _}
import akka.util.ByteString
import org.scalatest._
import org.scalatest.Matchers._

import scala.collection.immutable

class HttpSignatureSpecTest  extends FreeSpec {

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
        val headersForSig = Client.signatureHeaders(serverResponse.header[`WWW-Authenticate`].get).get
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


  }

}
