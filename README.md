# An Akka-Http Server for Twitter Sign In Implementation. 

To use this, consider having a webApp written in your favourite language/framework. Personally, I developed this with an Angular 6 webApp.

# Step one

From your App, call http://127.0.0.1:8081/requestToken, passing http://127.0.0.1:8081/TwitterRedirect as your Callback URL parameter. The server will make connection to Twitter and get the oauth_token and oauth_token_secret for you. Then, it will respond the URL which you should use to redirect your user to authentication.

# Step Two

After the user has successfully authenticated, Twitter will redirect to Callback URL (/TwitterRedirect), passing through the oauth_verifier and the oauth_token as parameters. The Server will then complete an html with a javascript's postMessage event, passing the verifier + token to the webApp. You should make an eventListener in your webApp, waiting for that message.

# Step Three

After getting the message from the Server, you should parse the Verifier and the Token separately, and then calling /getAccessToken with both tokens as parameters. The Server will then use both to get the Access_Token, Access_Token_Secret, User_Id and Screen_Name and it will serve them as JSON.

# Step Four.

Parse the JSON you get and then call /verifyCredentials with the access_token and access_token_secret, to get the user info. 

Your App should look something like this:

```javascript
callTwLogin(): void{ //function you call after user clicks on a button or something.
    // StepOne
    var win = window.open('','_blank','height=500,width=800'); //Open a Blank PopUp.
    /** Add a listener so the Server can send a PostMessage when completing Authorization */
    window.addEventListener("message", recieveMessage, false);
    
    function recieveMessage(event){
      if (~event.origin.indexOf("http://127.0.0.1:8081")) {
        let wholeString:string = event.data;
        let array = wholeString.split("|"); // Parsing what the Server gives you.
        const oauth_verifier = array[0];
        const oauth_token = array[1];
        win.close(); // Close the popUp as you won't need it anymore.
        
        /**Step Three: Post oauth_verifier to Twitter */
        let url = 'http://127.0.0.1:8081/getAccessToken';
        fetch(url+'?verifier='+oauth_verifier+'&token='+oauth_token)
          .then(
            function(response) {
              if (response.status != 200) {
                console.log("Looks like there was a problem. Status Code: "+ response.status);
                return
              }
              else response.json().then(function(data){ //If everything goes fine, you get access tokens.
                let accessToken = data['access_token'];
                let tokenSecret = data['token_secret'];
                /**Getting User Info**/
                fetch('http://127.0.0.1:8081/verifyCredentials?token='+accessToken+'&tokenSecret='+tokenSecret)
                    .then(function(response){
                      if (response.status != 200) {
                        console.log("Couldn't get user info. Status: "+ response.status);
                        return
                      }
                      else response.json()
                        .then(function(data){
                        console.log(data);
                      });
                    })
              });
            }
          )
      }
      else console.log("No host");
    }
    /** Step Two: Making a call to backend, specifying callback URL */
    const url = 'http://127.0.0.1:8081/requestToken?callback=';
    const callback = 'http://127.0.0.1:8081/TwitterRedirect';
    this.http.get(url+callback, {responseType: 'text'}).subscribe(data =>{
      win.location.replace(data); //Redirect the user to Twitter Authorization.  
    });

   }
   
  ```
