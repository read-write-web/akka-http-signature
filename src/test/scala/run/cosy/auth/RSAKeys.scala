package run.cosy.auth

import org.scalatest.FreeSpec
import org.scalatest.Matchers._
import org.scalatest._


class RSAKeysTest extends FreeSpec {
   //first we make a public/private key pair -- very low security (512) as this is just a test - recommended is 2048 and above
   val (pub,priv) = RSAKeys.buildRSAKeyPair(512)
      
   "encoding and decoding a key" - {
      
      "the private key" in {
         val privStr = RSAKeys.save(priv)
         val newPriv = RSAKeys.readPrivateKeyFrom(privStr)
         newPriv.get should be(priv)
      }
   
      "the public key" in {
         val pubStr = RSAKeys.save(pub)
         val newPub = RSAKeys.readPublicKeyFrom(pubStr)
         newPub.get should be(pub)
      }
      
   }
}
