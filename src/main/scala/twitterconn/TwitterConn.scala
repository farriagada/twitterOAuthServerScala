package twitterconn

import java.io.UnsupportedEncodingException
import java.net.URLEncoder
import java.util.{Base64, Date}

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.{BasicHttpCredentials, RawHeader}
import akka.stream.ActorMaterializer
import akka.http.scaladsl.server.Directives._
import ch.megard.akka.http.cors.scaladsl.CorsDirectives._
import ch.megard.akka.http.cors.scaladsl.settings.CorsSettings
import com.roundeights.hasher.Implicits._
import java.io.UnsupportedEncodingException
import scala.util.parsing.json._
import scala.concurrent.{Await, Future}
import scala.concurrent.duration.Duration
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import akka.util.ByteString

import scala.language.postfixOps
import scala.util.{Failure, Random, Success}

object TwitterConn {
  private val consumerKey:String = "9ZbFMEJoI8smW7wxmYy1AFjBn"
  private var oauth_nonce:String = null
  private var oauth_timestamp: String = null
  private val consumerSecret: String = "29qvrnCep9HLrww19rTHjOcEWGlbpaOCsnhHcj5OZGHL9H8Se9"

  def encodeUriComp(s: String): String = {
    var result:String = null
    try{
      result = URLEncoder.encode(s, "UTF-8")
                  .replaceAll("\\+", "%20")
                  .replaceAll("\\%21", "!")
                  .replaceAll("\\%27", "'")
                  .replaceAll("\\%28", "(")
                  .replaceAll("\\%29", ")")
                  .replaceAll("\\%7E", "~")

    }
    catch {
      case e: UnsupportedEncodingException => throw new UnsupportedEncodingException("Error when encoding URI")
    }
    //println("Encoded URI: "+result)
    return result
  }
  def randomString(length: Int): String ={
    var text = Random.alphanumeric.take(length).mkString("")
    //println("Random String: "+text)
    return text
  }

  def createTimestamp(): String = {
    //println((System.currentTimeMillis()/1000).toString())
    return (System.currentTimeMillis()/1000).toString()
  }

  def createSignature(): String = {
    val callback = this.encodeUriComp("http://127.0.0.1:4200/profile/083a3d5f-3966-4435-90f6-99461c467252")
    val rawURL: String = "POST&" + this.encodeUriComp("https://api.twitter.com/oauth/request_token")+"&"
    val parameterString: String = "oauth_callback=" + callback +
                                  "&oauth_consumer_key=" + this.consumerKey +
                                  "&oauth_nonce=" + this.oauth_nonce +
                                  "&oauth_signature_method=HMAC-SHA1"+
                                  "&oauth_timestamp=" + this.oauth_timestamp +
                                  "&oauth_version=1.0"

    val signingString = rawURL + this.encodeUriComp(parameterString)
    val signingKey = this.encodeUriComp(this.consumerSecret) + "&" // No token secret because its Request_Token
    println("Hmac: " + (signingString.hmac(signingKey)).sha1.hex)
    val secret = new SecretKeySpec(signingKey.getBytes("UTF-8"), "HmacSHA1") // We create the key
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(secret) // We init the HmacSHA1
    val hmac = mac.doFinal(signingString.getBytes("UTF-8")) // We create the Hmac with the string
    val signatur = Base64.getEncoder.encodeToString(hmac) // We Base64 encode the Hmac.
    println("Signatur: " +signatur)
    return signatur
  }

  def main(args: Array[String]): Unit ={
    implicit val actorSystem = ActorSystem("twitterAkka")

    implicit val actorMaterializer = ActorMaterializer()

    implicit val executionContext = actorSystem.dispatcher

    val settings = CorsSettings.defaultSettings.withAllowCredentials(false)
    val route = cors(settings){
      path("StepOne"){
        parameters('callback.as[String])(cb => {
          val callback = this.encodeUriComp(cb)
          val url = "https://api.twitter.com/oauth/request_token"
          var response: String = null
          this.oauth_timestamp = this.createTimestamp()
          this.oauth_nonce = this.randomString(32)
          val authorization = headers.RawHeader("Authorization",
            """OAuth oauth_callback="""" + callback +
              """", oauth_consumer_key="""" + this.consumerKey +
              """", oauth_nonce="""" + this.oauth_nonce +
              """", oauth_signature="""" + this.encodeUriComp(this.createSignature()) +
              """", oauth_signature_method="HMAC-SHA1", oauth_timestamp="""" + this.oauth_timestamp +
              """", oauth_version="1.0"""")
          val params = ByteString(callback)
          var jsonRSP = "null"
          val responseFuture: Future[HttpResponse] = Http().singleRequest(HttpRequest(HttpMethods.POST, url,
            headers = List(authorization),
            entity = HttpEntity(ContentTypes.`text/plain(UTF-8)`, params)))
          responseFuture
            .onComplete {
              case Success(res) => {
                val response = res._3.dataBytes.map(_.utf8String).runForeach(body => {
                  /* We postedit the string to make it JSON Parsable */
                  val postBody = "{"+body.replaceAll("=",":").replaceAll("&",",").replaceAll("(\\w+)", "\"$1\"")+"}"
                  jsonRSP = postBody
                  println(postBody)
                })
              }
              case Failure(_) => sys.error("Couldn't get into api.twitter")
            }
          Await.result(responseFuture, Duration.Inf)
          //s"response: " + response + s"!"
          complete(HttpResponse(StatusCodes.OK, entity = HttpEntity(ContentTypes.`application/json`,  jsonRSP)))
        })
      }
    }
    Http().bindAndHandle(route, "localhost", 8081)
  }
}
