using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Claims;
using System.Security.Cryptography;

string publicKey = File.ReadAllText(@"C:\Users\ormaz\source\repos\jwt\jwt\publicKey.pem");
string privateKey = File.ReadAllText(@"C:\Users\ormaz\source\repos\jwt\jwt\privateKey.pem");

var claims = new List<Claim>();
claims.Add(new Claim("name", "Ormazabal"));
claims.Add(new Claim("age", "32"));

var token = CreateToken(claims, privateKey);
var payload = DecodeToken(token, publicKey);

Console.WriteLine("token: " + token);
Console.WriteLine("payload: " + payload);

static string CreateToken(List<Claim> claims, string privateRsaKey)
{
    RSAParameters rsaParams;
    using (var tr = new StringReader(privateRsaKey))
    {
        var pemReader = new PemReader(tr);

        rsaParams = new RSAParameters();

        while (tr.Peek() != -1)
        {
            var parameter = pemReader.ReadObject() as RsaPrivateCrtKeyParameters;
            if (parameter != null)
            {
                var privateRsaParams = parameter as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);
            }
        }
    }
    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
    {
        rsa.ImportParameters(rsaParams);
        Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
        return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
    }
}

static string DecodeToken(string token, string publicRsaKey)
{
    RSAParameters rsaParams;

    using (var tr = new StringReader(publicRsaKey))
    {
        var pemReader = new PemReader(tr);
        var publicKeyParams = pemReader.ReadObject() as RsaKeyParameters;
        if (publicKeyParams == null)
        {
            throw new Exception("Could not read RSA public key");
        }
        rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParams);
    }
    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
    {
        rsa.ImportParameters(rsaParams);
        // This will throw if the signature is invalid
        return Jose.JWT.Decode(token, rsa, Jose.JwsAlgorithm.RS256);
    }
}
