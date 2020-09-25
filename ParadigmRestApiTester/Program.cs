using System;
using System.Configuration;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;


namespace ParadigmRestApiTester
{
    public class CustomHandler : DelegatingHandler
    {
        private readonly string appId = ConfigurationManager.AppSettings["appId"]?.ToString();
        private readonly string apiKey = ConfigurationManager.AppSettings["apiKey"]?.ToString();
        private readonly string userLoginId = ConfigurationManager.AppSettings["userLoginId"]?.ToString();

        public CustomHandler()
        {
            InnerHandler = new HttpClientHandler();
        }

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpResponseMessage response = null;
            string requestContentBase64String = string.Empty; ;

            string requestUri = HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());
            string requestHttpMethod = request.Method.Method;

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan timeSpan = DateTime.UtcNow - epochStart;
            string requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            string nonce = Guid.NewGuid().ToString("N");

            if (request.Content != null)
            {
                byte[] content = await request.Content.ReadAsByteArrayAsync();
                SHA256 hash = SHA256.Create();
                byte[] requestContentHash = hash.ComputeHash(content);
                requestContentBase64String = Convert.ToBase64String(requestContentHash);
            }

            string signatureRawData = $"{appId}{userLoginId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";
            var secretKeyByteArray = Convert.FromBase64String(apiKey);
            byte[] signature = Encoding.UTF8.GetBytes(signatureRawData);

            using (HMACSHA256 hmac = new HMACSHA256(secretKeyByteArray))
            {
                byte[] signatureBytes = hmac.ComputeHash(signature);
                string requestSignatureBase64String = Convert.ToBase64String(signatureBytes);
                request.Headers.AcceptLanguage.Add(new StringWithQualityHeaderValue("en-US"));
                request.Headers.Authorization = new AuthenticationHeaderValue("paradigm",
                    string.Format("{0}:{1}:{2}:{3}:{4}", appId, requestSignatureBase64String, nonce, requestTimeStamp, userLoginId));
            }

            response = await base.SendAsync(request, cancellationToken);
            return response;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            RunAsync().Wait();
        }

        static async Task RunAsync()
        {
            Console.WriteLine("API Call");


            var apiPath = ConfigurationManager.AppSettings["apiPath"]?.ToString();
            var searchJsonPayloadPath = ConfigurationManager.AppSettings["searchJsonPayloadPath"]?.ToString();
            HttpResponseMessage response;
            using (HttpClient client = new HttpClient(new CustomHandler()))
            {
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                ////StringContent searchContent = new StringContent(File.ReadAllText(searchJsonPayloadPath), Encoding.UTF8, "application/json");
                ////string payload = HttpUtility.UrlEncode(await searchContent.ReadAsStringAsync());
                //string payload = "%7b%0d%0a%09%22RegistrationNumber%22%3a%22121840804%22%0d%0a%7d";
                //var searchJsonPayloadPath = ConfigurationManager.AppSettings["searchJsonPayloadPath"]?.ToString();
                StringContent searchContent = new StringContent(File.ReadAllText(searchJsonPayloadPath), Encoding.UTF8, "application/json");
                string payload = HttpUtility.UrlEncode(await searchContent.ReadAsStringAsync());
                response = await client.GetAsync($"{apiPath}?content={payload}");
            }

            if (response != null)
            {
                if (response.IsSuccessStatusCode)
                {
                    string responseString = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(responseString);
                    Console.WriteLine("HTTP Status: {0}, Reason {1}. Press ENTER to exit", response.StatusCode, response.ReasonPhrase);
                }
                else
                {
                    Console.WriteLine("Failed to call the API. HTTP Status: {0}, Reason {1}", response.StatusCode, response.ReasonPhrase);
                }
            }
            else
            {
                Console.WriteLine("No call");
            }

            Console.ReadLine();
        }
    }
}
