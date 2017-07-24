package run.cosy.auth

import java.security._
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.util.Base64

import scala.util.Try


//just to get going and to make our life easier we start only with RSA keys
//this will allow us to see patterns for coding and then try something more
//advanced.
object RSAKeys {
   //note: the problem with the Java Keystore is that it forces us to work with
   //certificates which are complicated to make and not necessarily that useful.
   // eg: the DN is pretty useless, and there is no place to put info we want
   //  such as the keyid. Furthermore we may not know where the WebID is until later.
   //  this seems to indicate that it would be better perhaps to write the content
   //  out in a format that is easier to read and extensible, and have the private key
   //  in the same format but encrypted potentially with a symmetric key.
   //
   //  we can get going by just dropping the public and private key into PEM files
   //  and develop more advanced solutions later
   
   def buildRSAKeyPair(size: Int = 2048): (RSAPublicKey, RSAPrivateKey) = {
      val kpg: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
      kpg.initialize(size)
      val kp = kpg.genKeyPair
      (kp.getPublic.asInstanceOf[RSAPublicKey], kp.getPrivate.asInstanceOf[RSAPrivateKey])
   }
   
   
   // good info here:
   //https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
   
   // Saving and reading keys is actually very simple
   //
   // in each case we embed the key in a spec that allows it to be encoded as a specific ASN.1 structure
   // X509PubKey for the public key and PKCS8 for the private key. This is then base64 encoded.
   // one can think of ASN.1 as like XML, but in binary, and so a lot more difficult to read and understand
   // without proper tooling: eg. there are no human readable entities or attributes. Instead these are numbers
   // that have to be registered somewhere... So it is difficult to extend.
   // On the other hand because it is binary, it is easy to sign.
   //
   def save(pubKey: RSAPublicKey): String =
      new String(Base64.getMimeEncoder.encode(new X509EncodedKeySpec(pubKey.getEncoded).getEncoded),"US-ASCII")
   
   def save(privKey: RSAPrivateKey): String =
      new String(Base64.getMimeEncoder.encode(new PKCS8EncodedKeySpec(privKey.getEncoded).getEncoded),"US-ASCII")
   
   def readPrivateKeyFrom(key: String): Try[PrivateKey] = Try {
      val kf = KeyFactory.getInstance("RSA")
      kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder.decode(key)))
   }
   
   def readPublicKeyFrom(key: String): Try[PublicKey] = Try {
      val kf = KeyFactory.getInstance("RSA")
      kf.generatePublic(new X509EncodedKeySpec(Base64.getMimeDecoder.decode(key)))
   }
   
}
