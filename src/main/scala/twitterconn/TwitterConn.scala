package twitterconn


import java.net.URLEncoder
import java.util.Base64

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.stream.ActorMaterializer
import akka.http.scaladsl.server.Directives._
import ch.megard.akka.http.cors.scaladsl.CorsDirectives._
import ch.megard.akka.http.cors.scaladsl.settings.CorsSettings
import java.io.UnsupportedEncodingException
import scala.concurrent.Future
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import akka.util.ByteString
import scala.language.postfixOps
import scala.util.{Failure, Random, Success}

object TwitterConn {
  private val consumerKey:String = "AE9dKFE0qkBX2AWLskj8kPlQg"
  private var oauth_nonce:String = null
  private var new_nonce:String = null
  private var third_nonce:String = null
  private var oauth_timestamp: String = null
  private var new_timestamo: String = null
  private val consumerSecret: String = "KqoUebfGv0cEsazgjUfdmu4MlwIv60m4dQ1nLDI6gxcblUUh1F"
  private var oauth_verifier = "null"
  private var oauth_token = "null"
  private var oauth_token_secret = "null"

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

  def createSignatureRequestToken(callback: String): String = {
    val rawURL: String = "POST&" + this.encodeUriComp("https://api.twitter.com/oauth/request_token")+"&"
    val parameterString: String = "oauth_callback=" + callback +
                                  "&oauth_consumer_key=" + this.consumerKey +
                                  "&oauth_nonce=" + this.oauth_nonce +
                                  "&oauth_signature_method=HMAC-SHA1"+
                                  "&oauth_timestamp=" + this.oauth_timestamp +
                                  "&oauth_version=1.0"

    val signingString = rawURL + this.encodeUriComp(parameterString)
    val signingKey = this.encodeUriComp(this.consumerSecret) + "&" // No token secret because its Request_Token
    val secret = new SecretKeySpec(signingKey.getBytes("UTF-8"), "HmacSHA1") // We create the key
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(secret) // We init the HmacSHA1
    val hmac = mac.doFinal(signingString.getBytes("UTF-8")) // We create the Hmac with the string
    val signatur = Base64.getEncoder.encodeToString(hmac) // We Base64 encode the Hmac.
    return signatur
  }

  def createSignatureAccessToken(): String = {
    val rawURL: String = "POST&" + this.encodeUriComp("https://api.twitter.com/oauth/access_token")+"&"
    val parameterString: String =
      "oauth_consumer_key=" + this.consumerKey +
      "&oauth_nonce=" + this.new_nonce +
      "&oauth_signature_method=HMAC-SHA1"+
      "&oauth_timestamp=" + this.oauth_timestamp +
      "&oauth_token=" + this.oauth_token +
      "&oauth_version=1.0"

    val signingString = rawURL + this.encodeUriComp(parameterString)
    val signingKey = this.encodeUriComp(this.consumerSecret) + "&" + this.encodeUriComp(this.oauth_token_secret)
    val secret = new SecretKeySpec(signingKey.getBytes("UTF-8"), "HmacSHA1") // We create the key
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(secret) // We init the HmacSHA1
    val hmac = mac.doFinal(signingString.getBytes("UTF-8")) // We create the Hmac with the string
    val signatur = Base64.getEncoder.encodeToString(hmac) // We Base64 encode the Hmac.
    return signatur
  }

  def createSignatureUser(): String = {
    val rawURL: String = "GET&" + this.encodeUriComp("https://api.twitter.com/1.1/account/verify_credentials.json")+"&"
    val parameterString: String =
      "oauth_consumer_key=" + this.consumerKey +
        "&oauth_nonce=" + this.third_nonce +
        "&oauth_signature_method=HMAC-SHA1"+
        "&oauth_timestamp=" + this.new_timestamo +
        "&oauth_token=" + this.oauth_token +
        "&oauth_version=1.0"
    val signingString = rawURL + this.encodeUriComp(parameterString)
    val signingKey = this.encodeUriComp(this.consumerSecret) + "&" + this.encodeUriComp(this.oauth_token_secret)
    val secret = new SecretKeySpec(signingKey.getBytes("UTF-8"), "HmacSHA1") // We create the key
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(secret) // We init the HmacSHA1
    val hmac = mac.doFinal(signingString.getBytes("UTF-8")) // We create the Hmac with the string
    val signatur = Base64.getEncoder.encodeToString(hmac) // We Base64 encode the Hmac.
    return signatur
  }

  def setRequestTokenRSP(str: String): Array[String] = {
    var i, j = 0
    var token, secret, callback = ""
    str.split("&").foreach(sub =>{
      sub.split("=").foreach(subsub => {
          if(i==0){ //oauth_token
            if(j==1) token = subsub
          }
          if(i==1){ //oauth_token_secret
            if(j==1) secret = subsub
          }
          if(i==2){ //oauth_callback_confirmed
            if(j==1) callback = subsub
          }
        j=j+1
      })
      j=0
      i=i+1
    })
    return Array(token,secret,callback)
  }

  def makeAccessJSON(str: String): Array[String] = {
    var i, j = 0
    var token, secret,user_id, screen_name = ""
    str.split("&").foreach(sub =>{
      sub.split("=").foreach(subsub => {
        if(i==0){ //oauth_token
          if(j==1) token = subsub
        }
        if(i==1){ //oauth_token_secret
          if(j==1) secret = subsub
        }
        if(i==2){ //oauth_callback_confirmed
          if(j==1) user_id = subsub
        }
        if(i==3){
          if(j==1) screen_name = subsub
        }
        j=j+1
      })
      j=0
      i=i+1
    })
    return Array(token,secret,user_id,screen_name)
  }

  def main(args: Array[String]): Unit ={
    implicit val actorSystem = ActorSystem("twitterAkka")

    implicit val actorMaterializer = ActorMaterializer()

    implicit val executionContext = actorSystem.dispatcher

    val settings = CorsSettings.defaultSettings.withAllowCredentials(false)
    val route = cors(settings){

      path("requestToken"){
        get {
          parameters('callback.as[String])(cb => {
              val callback = this.encodeUriComp(cb)
              val url = "https://api.twitter.com/oauth/request_token"
              this.oauth_timestamp = this.createTimestamp()
              this.oauth_nonce = this.randomString(32)
              val authorization = headers.RawHeader("Authorization",
                """OAuth oauth_callback="""" + callback +
                  """", oauth_consumer_key="""" + this.consumerKey +
                  """", oauth_nonce="""" + this.oauth_nonce +
                  """", oauth_signature="""" + this.encodeUriComp(this.createSignatureRequestToken(callback)) +
                  """", oauth_signature_method="HMAC-SHA1", oauth_timestamp="""" + this.oauth_timestamp +
                  """", oauth_version="1.0"""")
              val params = ByteString(callback)
              val responseFuture: Future[HttpResponse] = Http().singleRequest(HttpRequest(HttpMethods.POST, url,
                  headers = List(authorization),
                  entity = HttpEntity(ContentTypes.`text/plain(UTF-8)`, params)))
              onComplete(responseFuture) {
                  case Success(result) => {
                      // We cut off "HttpEntity.Strict(text/html; charset=UTF-8" from the result string. If anything changes in Akka, this must be changed too.
                      val Str = result.entity.httpEntity.toString()
                      val response = Str.substring(Str.indexOf("o"), Str.indexOf(")")) //This is the final response.
                      val arr = setRequestTokenRSP(response)
                      this.oauth_token = arr(0)
                      this.oauth_token_secret = arr(1)
                      if (arr(2) == "true") { // if oauth_callback_confirmed == true
                          val uri = "https://api.twitter.com/oauth/authenticate?oauth_token=" + arr(0)
                          complete(HttpEntity(ContentTypes.`text/plain(UTF-8)`, uri))
                      }
                      else complete("Error receiving Request Token")
                  }
                  case Failure(ex) => complete(HttpEntity(ContentTypes.`text/plain(UTF-8)`, "Couldn't process request. Exception is: " +ex))
              }
          })
        }
      }~
      path("TwitterRedirect"){
        get{
          parameters('oauth_verifier.as[String], 'oauth_token.as[String])((verifier, token) => {
            if(this.oauth_token==token) { // Check whether token received in authorization equals the previous one.
              this.oauth_verifier = verifier
              val rspToAngular = verifier + "|" + token
              val html =
                "<!doctype html>" +
                  "<html lang='en'>" +
                  "<head>" +
                  "<meta charset='UTF-8'> <title>Popup</title> </head>" +
                  "<body> <script type='text/javascript'>" +
                  "window.opener.postMessage('" + rspToAngular + "', 'http://localhost:4200');" +
                  "</script></body></html>"
              complete(HttpEntity(ContentTypes.`text/html(UTF-8)`, html))
            }
            else {
              val html =
                "<!doctype html>" +
                  "<html lang='en'>" +
                  "<head>" +
                  "<meta charset='UTF-8'> <title>Popup</title> </head>" +
                  "<body> <script type='text/javascript'>" +
                  "window.opener.postMessage('Error: Token Mismatch', 'http://localhost:4200');" +
                  "</script></body></html>"
              complete(HttpEntity(ContentTypes.`text/html(UTF-8)`,html))
            }
          })
        }
      }~
      path("getAccessToken"){
        get{
          parameters('verifier.as[String], 'token.as[String])((verifier,token) => {
            val url = "https://api.twitter.com/oauth/access_token"
            this.new_nonce = this.randomString(32)
            val authorization = headers.RawHeader("Authorization",
                """OAuth oauth_consumer_key="""" + this.consumerKey +
                """", oauth_nonce="""" + this.new_nonce +
                """", oauth_signature="""" + this.encodeUriComp(this.createSignatureAccessToken()) +
                """", oauth_signature_method="HMAC-SHA1", oauth_timestamp="""" + this.oauth_timestamp +
                """", oauth_token=""""+ token +
                """", oauth_version="1.0"""")
            val responseFuture: Future[HttpResponse] = Http().singleRequest(HttpRequest(HttpMethods.POST, url,
              headers = List(authorization),
              entity = FormData(Map("oauth_verifier" -> verifier)).toEntity(HttpCharsets.`UTF-8`)))
            onComplete(responseFuture){
              case Success(res) => {
                val Str = res.entity.httpEntity.toString()
                val response = Str.substring(Str.indexOf("o"), Str.indexOf(")")) //This is the final response.
                val arr = makeAccessJSON(response)
                val jsonRSP = """ {"access_token":""""+arr(0)+"""" , "token_secret":""""+arr(1)+"""" ,"user_id":""""+arr(2)+"""" , "screen_name":""""+arr(3)+""""}"""
                complete(HttpEntity(ContentTypes.`text/plain(UTF-8)`,jsonRSP))
              }
              case Failure(ex) => complete(s"Error Occurred")
            }
          })
        }
      }~
      path("verifyCredentials"){
        get{
          parameters('token.as[String],'tokenSecret.as[String])((token, tokenSecret) => {
            this.oauth_token = token
            this.oauth_token_secret = tokenSecret
            this.third_nonce = this.randomString(32)
            this.new_timestamo = this.createTimestamp()
            val url = "https://api.twitter.com/1.1/account/verify_credentials.json"
            val authorization = headers.RawHeader("Authorization",
              """OAuth oauth_consumer_key="""" + this.consumerKey +
                """", oauth_nonce="""" + this.third_nonce +
                """", oauth_signature="""" + this.encodeUriComp(this.createSignatureUser()) +
                """", oauth_signature_method="HMAC-SHA1", oauth_timestamp="""" + this.new_timestamo +
                """", oauth_token=""""+ token +
                """", oauth_version="1.0"""")
            val request: Future[HttpResponse] = Http().singleRequest(HttpRequest(HttpMethods.GET, url, headers = List(authorization)))
            onComplete(request) {
              case Success(res) => {
                val Str = res.entity.httpEntity.toString
                val response = Str.substring(Str.indexOf("{"), (Str.length()-1)) //This is the final response.
                complete(HttpEntity(ContentTypes.`application/json`, response))
              }
              case Failure(ex) => complete("Couldn't get user info. Reason:  " + ex)
            }
          })
        }
      }
      /** END OF ROUTING **/
    }
    Http().bindAndHandle(route, "127.0.0.1", 8081)

  }
}
