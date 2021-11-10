using DotNetCertAuthSample.Models;
using Jose;
using Polly;
using Polly.Retry;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCertAuthSample.Services
{
    public class HTTPService
    {
        private TokenModel? _token;
        private readonly HttpClient _httpClient;
        private readonly AsyncRetryPolicy<HttpResponseMessage> _retryPolicy;
        public HTTPService(HttpClient httpClient)
        {
            _httpClient = httpClient;
            HttpStatusCode[] httpStatusCodesWorthRetrying = {
               HttpStatusCode.RequestTimeout, // 408
               HttpStatusCode.InternalServerError, // 500
               HttpStatusCode.BadGateway, // 502
               HttpStatusCode.ServiceUnavailable, // 503
               HttpStatusCode.GatewayTimeout // 504
            };
            _retryPolicy = Policy
                .Handle<HttpRequestException>()
                .OrInner<TaskCanceledException>()
                .OrResult<HttpResponseMessage>(r => httpStatusCodesWorthRetrying.Contains(r.StatusCode))
                  .WaitAndRetryAsync(new[]
                  {
                    TimeSpan.FromSeconds(2),
                    TimeSpan.FromSeconds(4),
                    TimeSpan.FromSeconds(8)
                  });
        }

        private void GetTokenAsync(X509Certificate2 clientCertificate)
        {
            if(_token == null || _token.ExpiresOn < DateTimeOffset.Now)
            {
                CreateRSAJWTToken(clientCertificate);
            }
        }

        public async Task<APIResultModel> SendGetAsync(string url, X509Certificate2 clientCertificate)
        {
            GetTokenAsync(clientCertificate);
            APIResultModel apiResult = new ();
            HttpResponseMessage responseMessage;
            HttpRequestMessage requestMessage = new (HttpMethod.Get, url);
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _token.AccessToken);
            try
            {
                responseMessage = await _retryPolicy.ExecuteAsync(async () =>
                          await SendMessageAsync(requestMessage));
                apiResult.Message = await responseMessage.Content.ReadAsStringAsync();
                apiResult.Success = responseMessage.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                apiResult.Success = false;
                if (ex.Message.Contains("One or more errors") 
                    && ex.InnerException != null)
                {
                    apiResult.Message = ex.InnerException.Message;
                }
                else
                {
                    apiResult.Message = ex.Message;
                }
            }
            return apiResult;
        }


        private void CreateRSAJWTToken(X509Certificate2 clientCertificate)
        {
            var headers = new Dictionary<string, object>
            {
                { "typ", "JWT" },
                { "x5t", clientCertificate.Thumbprint }
            };
            _token = new();
            var payload = new Dictionary<string, object>()
            {
                {"aud", $"https://ezca.io"},
                {"jti", Guid.NewGuid().ToString()},
                {"nbf", (ulong)_token.NotBefore.ToUnixTimeSeconds()},
                {"exp", (ulong)_token.ExpiresOn.ToUnixTimeSeconds()}
            };
            _token.AccessToken =  JWT.Encode(payload, clientCertificate.GetRSAPrivateKey(), 
                JwsAlgorithm.RS256, extraHeaders: headers);
        }

        private async Task<HttpResponseMessage> SendMessageAsync(HttpRequestMessage requestMessage)
        {
            HttpResponseMessage response;
            response = await _httpClient.SendAsync(requestMessage);
            return response;
        }

    }
}
