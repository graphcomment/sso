var GC_SECRET = "12345";
var GC_PUBLIC = "abcde";

function gcSignon(user) {

  var gcData = {
    id: user.id, // required unique
    username: user.username, // required unique
    email: user.email, // required unique

    language: user.language, //(optionnal) default value : en (codes ISO 639-1)
    bio: user.bio, // (optionnal) description
    picture: user.picture // (optionnal) full url only
  };

  var gcStr = JSON.stringify(gcData);
  var timestamp = Math.round(+new Date() / 1000);

  /*
   * Note that `Buffer` is part of node.js
   * For pure Javascript or client-side methods of
   * converting to base64, refer to this link:
   * http://stackoverflow.com/questions/246801/how-can-you-encode-a-string-to-base64-in-javascript
   */
  var message = new Buffer(gcStr).toString('base64');

  /*
   * CryptoJS is required for hashing (included in dir)
   * https://code.google.com/p/crypto-js/
   */
  var result = CryptoJS.HmacSHA1(message + " " + timestamp, GC_SECRET);
  var hexsig = CryptoJS.enc.Hex.stringify(result);

  return {
    pubKey: GC_PUBLIC,
    auth: message + " " + hexsig + " " + timestamp
  };
}