using DnsClient;
using EmailAddressVerificationAPI.Models;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EmailAddressVerificationAPI.Services
{
    public class SmtpServerVerification
    {
        private async Task<EmailStatusCode> CheckDkimAsync(string domain)
        {
            string selector = "default";
            string dkimDomain = $"{selector}._domainkey.{domain}";

            try
            {
                var lookup = new LookupClient();
                var queryResult = await lookup.QueryAsync(dkimDomain, QueryType.TXT);

                var txtRecords = queryResult.Answers.TxtRecords();

                foreach (var record in txtRecords)
                {
                    string txtData = string.Join(" ", record.Text);
                    return EmailStatusCode.Valid;
                }

                return EmailStatusCode.Invalid;
            }
            catch (Exception)
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private async Task<EmailStatusCode> CheckDmarcAsync(string domain)
        {
            string dmarcDomain = $"_dmarc.{domain}";

            try
            {
                var lookup = new LookupClient();
                var queryResult = await lookup.QueryAsync(dmarcDomain, QueryType.TXT);

                var txtRecords = queryResult.Answers.TxtRecords();

                foreach (var record in txtRecords)
                {
                    string txtData = string.Join(" ", record.Text);
                    if (txtData.Contains("v=DMARC1"))
                    {
                        return EmailStatusCode.Valid;
                    }
                }
                return EmailStatusCode.Invalid;
            }
            catch (Exception)
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private async Task<EmailStatusCode> CheckSingleMXAsync(string email, string domain, KeyValuePair<int, string> mxRecord, int port)
        {
            TcpClient? client = null;
            Stream? stream = null;
            try
            {
                client = new TcpClient();
                await client.ConnectAsync(mxRecord.Value, port);
                stream = client.GetStream();

                if (port == 465)
                {
                    var sslStream = new SslStream(stream, false, ValidateServerCertificate);

                    await sslStream.AuthenticateAsClientAsync(mxRecord.Value);
                    stream = sslStream;
                }

                string response = await ReceiveResponseAsync(stream);
                if (string.IsNullOrEmpty(response) || !(response.StartsWith("220") || response.StartsWith("250")))
                {
                    return EmailStatusCode.Null;
                }

                await SendCommandAsync(stream, "HELO verifier.com\r\n");
                response = await ReceiveResponseAsync(stream);
                if (!response.StartsWith("250"))
                {
                    return EmailStatusCode.Null;
                }

                string sender = $"verify@{domain}";
                await SendCommandAsync(stream, $"MAIL FROM:<{sender}>\r\n");
                response = await ReceiveResponseAsync(stream);
                if (!response.StartsWith("250"))
                {
                    return EmailStatusCode.Null;
                }

                await SendCommandAsync(stream, $"RCPT TO:<{email}>\r\n");
                response = await ReceiveResponseAsync(stream);

                await SendCommandAsync(stream, "QUIT\r\n");
                client.Close();

                if (response.StartsWith("250"))
                {
                    return EmailStatusCode.Valid;
                }
                else if (response.StartsWith("550") || response.Contains("5.1.1") || response.ToLower().Contains("user unknown"))
                {
                    return EmailStatusCode.Invalid;
                }
                else if (response.StartsWith("552"))
                {
                    return EmailStatusCode.Invalid;
                }
                else if (response.StartsWith("452"))
                {
                    return EmailStatusCode.Null;
                }
                else
                {
                    return EmailStatusCode.Null;
                }
            }
            catch (Exception)
            {
                return EmailStatusCode.InternalServerError;
            }
            finally
            {
                client?.Close();
            }
        }

        private async Task SendCommandAsync(Stream stream, string command)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(command);
            await stream.WriteAsync(buffer, 0, buffer.Length);
            await stream.FlushAsync();
        }

        private async Task<string> ReceiveResponseAsync(Stream stream)
        {
            byte[] buffer = new byte[1024];
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
            return Encoding.ASCII.GetString(buffer, 0, bytesRead);
        }

        private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private async Task<EmailStatusCode> CheckSpfAsync(string domain)
        {
            try
            {
                var lookup = new LookupClient();
                var queryResult = await lookup.QueryAsync(domain, QueryType.TXT);
                var records = queryResult.Answers.TxtRecords();

                foreach (var record in records)
                {
                    string txtData = string.Join(" ", record.Text);
                    if (txtData.Contains("v=spf1"))
                    {
                        return EmailStatusCode.Valid;
                    }
                }

                return EmailStatusCode.Invalid;
            }
            catch (Exception)
            {
                return EmailStatusCode.InternalServerError;
            }
        }

        private async Task<Dictionary<int, string>> GetMXRecordsAsync(string domain)
        {
            Dictionary<int, string> mxRecords = new();

            try
            {
                LookupClient client = new LookupClient();
                var queryResult = await client.QueryAsync(domain, QueryType.MX);

                foreach (var record in queryResult.Answers.MxRecords())
                {
                    mxRecords[record.Preference] = record.Exchange.Value;
                }

                if (mxRecords.Count == 0)
                {
                    string[] parts = domain.Split('.');
                    if (parts.Length > 2)
                    {
                        string parentDomain = string.Join(".", parts[^2], parts[^1]);
                        queryResult = await client.QueryAsync(parentDomain, QueryType.MX);
                        foreach (var record in queryResult.Answers.MxRecords())
                        {
                            mxRecords[record.Preference] = record.Exchange.Value;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return mxRecords;
            }
            var sortedMxRecords = mxRecords.OrderBy(kvp => kvp.Key).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            return sortedMxRecords;
        }

        public async Task<List<EmailStatusCode>> SmtpServerAsync(string email, string domain)
        {
            List<EmailStatusCode> verificationResults = new()
            {
                EmailStatusCode.Invalid,
                EmailStatusCode.Invalid,
                EmailStatusCode.Invalid,
                EmailStatusCode.Invalid,
                EmailStatusCode.Invalid
            };

            try
            {

                Dictionary<int, string> mxRecords = await GetMXRecordsAsync(domain);

                if (mxRecords.Count == 0)
                {
                    return verificationResults;
                }
                verificationResults[0] = EmailStatusCode.Valid;
                int port = 25;

                var result = await CheckSingleMXAsync(email, domain, mxRecords.FirstOrDefault(), port);
                if ((int)result == 200)
                {
                    verificationResults[1] = EmailStatusCode.Valid;
                    if (((int)await CheckSpfAsync(domain) == 200))
                    {
                        verificationResults[2] = EmailStatusCode.Valid;
                    }
                    if (((int)await CheckDkimAsync(domain) == 200))
                    {
                        verificationResults[3] = EmailStatusCode.Valid;
                    }
                    if (((int)await CheckDmarcAsync(domain) == 200))
                    {
                        verificationResults[4] = EmailStatusCode.Valid;
                    }
                    return verificationResults;
                }
                else if ((int)result == 400)
                {
                    return verificationResults;
                }


                return verificationResults;
            }
            catch (Exception)
            {
                return verificationResults;
            }
        }
    }
}