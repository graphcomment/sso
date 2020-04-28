using System;
using System.Web.Script.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace Graphcomment
{
    public static class SSO
    {

        private const string _apiSecret = "GC_SECRET"; // TODO enter your API secret key

        /// <summary>
        /// Gets the Graphcomment SSO payload to authenticate users
        /// </summary>
        /// <param name="user_id">The unique ID to associate with the user</param>
        /// <param name="user_name">required unique name shown next to comments.</param>
        /// <param name="user_email">User's email address, defined by RFC 5322</param>
        /// <param name="user_language">User's language, defined by ISO 639-1</param>
        /// <param name="avatar_url">FULL URL of the avatar image</param>
        /// <returns>A string containing the signed payload</returns>
        public static string GetSsoData(string user_id, string user_name, string user_email, string user_language = "", string avatar_url = "")
        {
            var userdata = new
            {
                id = user_id,
                username = user_name,
                email = user_email,
                language = user_language,
                picture = avatar_url
            };

            string serializedUserData = new JavaScriptSerializer().Serialize(userdata);
            return GenerateSsoData(serializedUserData);
        }

        /// <summary>
        /// Method to log out a user from SSO
        /// </summary>
        /// <returns>A signed, empty sso-data string</returns>
        public static string LogoutUser()
        {
            var userdata = new { };
            string serializedUserData = new JavaScriptSerializer().Serialize(userdata);
            return GenerateSsoData(serializedUserData);
        }

        private static string GenerateSsoData(string serializedUserData)
        {
            byte[] userDataAsBytes = Encoding.ASCII.GetBytes(serializedUserData);

            // Base64 Encode the message
            string Message = System.Convert.ToBase64String(userDataAsBytes);

            // Get the proper timestamp
            TimeSpan ts = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0));
            string Timestamp = Convert.ToInt32(ts.TotalSeconds).ToString();

            // Convert the message + timestamp to bytes
            byte[] messageAndTimestampBytes = Encoding.ASCII.GetBytes(Message + " " + Timestamp);

            // Convert Graphcomment API key to HMAC-SHA1 signature
            byte[] apiBytes = Encoding.ASCII.GetBytes(_apiSecret);
            using (HMACSHA1 hmac = new HMACSHA1(apiBytes)) {
                byte[] hashedMessage = hmac.ComputeHash(messageAndTimestampBytes);

                // Put it all together into the final payload
                return Message + " " + ByteToString(hashedMessage).ToLower() + " " + Timestamp;
            }
        }

        private static string ByteToString(byte[] buff)
        {
            string sbinary = "";

            for (int i = 0; i < buff.Length; i++)
            {
                sbinary += buff[i].ToString("X2"); // hex format
            }
            return (sbinary);
        }
    }
}
