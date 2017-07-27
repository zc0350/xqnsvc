using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Text;
using System.IO;
using Microsoft.Win32;
using System.Xml;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net;


namespace xqnsvc
{
    public partial class xqnsvc : ServiceBase
    {

        const string website = "https://www.xqns.com";
        const string loginurl = "https://login.xqns.com/login.php";
        const string sname = "xqnsvc";
        const string fname = "\\xqns.xml";
        string u = "";
        string p = "";
        string k = "";
        string url = "";
        public xqnsvc()
        {
            InitializeComponent();
        }

        System.Timers.Timer timer = new System.Timers.Timer();

        protected override void OnStart(string[] args)
        {
            timer.Elapsed += new System.Timers.ElapsedEventHandler(timer_Elapsed);//使用Elapsed事件，其中timer_Elapsed就是你需要处理的事情
            timer.AutoReset = true;
            timer.Interval = 5000;    //5秒后尝试连接服务器
            timer.Enabled = true;
            //log("服务正常启动");
        }

        protected override void OnStop()
        {
         //log("服务已停止");
        }

        private void timer_Elapsed(object sender, EventArgs e)
        {          
            login();
        }

        private static string getpath()
        {
            string key = @"SYSTEM\CurrentControlSet\Services\xqnsvc";
            string path = Registry.LocalMachine.OpenSubKey(key).GetValue("ImagePath").ToString();
            //替换掉双引号   
            path = path.Replace("\"", string.Empty);
            FileInfo fi = new FileInfo(path);
            return fi.Directory.ToString();
        }


        private static byte[] Keys = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

        public static string DeDES(string decryptString, string decryptKey)
        {
            try
            {
                byte[] rgbKey = Encoding.UTF8.GetBytes(decryptKey.Substring(0, 8));
                byte[] rgbIV = Keys;
                byte[] inputByteArray = Convert.FromBase64String(decryptString);
                DESCryptoServiceProvider DCSP = new DESCryptoServiceProvider();
                MemoryStream mStream = new MemoryStream();
                CryptoStream cStream = new CryptoStream(mStream, DCSP.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Write);
                cStream.Write(inputByteArray, 0, inputByteArray.Length);
                cStream.FlushFinalBlock();
                return Encoding.UTF8.GetString(mStream.ToArray());
            }
            catch
            {
                return "";
            }
        }


        private void login()
        {
            timer.Interval = 30000;   ///不管请求结果如何，30后重试，如果连接成功，5分钟后重试

            string text = getpath() + fname;
            if (File.Exists(text))
            {
                XmlDocument xml = new XmlDocument();
                try
                {
                    xml.Load(text);
                    XmlNodeList node = xml.SelectSingleNode("PostData").ChildNodes;
                    foreach (XmlNode list in node)
                    {
                        if (list.Name == "User") u = list.InnerText.Trim();
                        if (list.Name == "Pass") p = DeDES(list.InnerText.Trim(), website);
                        if (list.Name == "Key") k = list.InnerText.Trim();
                    }
                }
                catch { }
            }
            else return;

            if (u == "" || p == "" || k == "")
            {
                return;
            }else { 
            ///构造get请求，see URL: https://www.xqns.com/article/5
            url = loginurl + "?type=domain&c=md5&cz=login&ver=V3.0&user=" + u + "&pass=" + md5(p + k);
            try
            {
                System.Net.HttpWebResponse res = HttpHelper.CreateGetHttpResponse(url, 5000, null, null);
                if (res == null)
                {
                        //log("服务器连接失败，返回未知错误");
                        //MessageBox.Show("IP更新出错，连接超时，等待下次尝试");
                        return;
                }
                else
                {
                   string mes = HttpHelper.GetResponseString(res);
                   timer.Interval = 300000;   ///请求成功后，5分钟重试 ///不管结果，就算报错也5分钟后再尝试
                   //log("请求成功，返回 "+mes);
                }
                }
            catch
            {
               //log("网络连接失败，30秒后重新连接");
                    //    MessageBox.Show("IP更新出错，网络错误");
                }
            }
        }
        private static string md5(string a)
        {
            return System.Web.Security.FormsAuthentication.HashPasswordForStoringInConfigFile(a, "MD5").ToLower();
        }

        private void log(string str)
        {
            string fname = getpath() + "\\log.txt";
            StreamWriter sw = File.AppendText(fname);
            sw.Write(DateTime.Now.ToLocalTime().ToString() + " "+ str + "\r\n");
            sw.Close();
        }

        public class HttpHelper
        {
            /// <summary>  
            /// 创建GET方式的HTTP请求  
            /// </summary>  
            public static HttpWebResponse CreateGetHttpResponse(string url, int timeout, string userAgent, CookieCollection cookies)
            {
                HttpWebRequest request = null;
                if (url.StartsWith("https", StringComparison.OrdinalIgnoreCase))
                {
                    //对服务端证书进行有效性校验（非第三方权威机构颁发的证书，如自己生成的，不进行验证，这里返回true）
                    ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CheckValidationResult);
                    request = WebRequest.Create(url) as HttpWebRequest;
                    request.ProtocolVersion = HttpVersion.Version10;    //http版本，默认是1.1,这里设置为1.0
                }
                else
                {
                    request = WebRequest.Create(url) as HttpWebRequest;
                }
                request.Method = "GET";

                //设置代理UserAgent和超时
                //request.UserAgent = userAgent;
                //request.Timeout = timeout;
                if (cookies != null)
                {
                    request.CookieContainer = new CookieContainer();
                    request.CookieContainer.Add(cookies);
                }
                return request.GetResponse() as HttpWebResponse;
            }

            /// <summary>  
            /// 创建POST方式的HTTP请求  
            /// </summary>  
            public static HttpWebResponse CreatePostHttpResponse(string url, IDictionary<string, string> parameters, int timeout, string userAgent, CookieCollection cookies)
            {
                HttpWebRequest request = null;
                //如果是发送HTTPS请求  
                if (url.StartsWith("https", StringComparison.OrdinalIgnoreCase))
                {
                    //ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CheckValidationResult);
                    request = WebRequest.Create(url) as HttpWebRequest;
                    //request.ProtocolVersion = HttpVersion.Version10;
                }
                else
                {
                    request = WebRequest.Create(url) as HttpWebRequest;
                }
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";

                //设置代理UserAgent和超时
                //request.UserAgent = userAgent;
                //request.Timeout = timeout; 

                if (cookies != null)
                {
                    request.CookieContainer = new CookieContainer();
                    request.CookieContainer.Add(cookies);
                }
                //发送POST数据  
                if (!(parameters == null || parameters.Count == 0))
                {
                    StringBuilder buffer = new StringBuilder();
                    int i = 0;
                    foreach (string key in parameters.Keys)
                    {
                        if (i > 0)
                        {
                            buffer.AppendFormat("&{0}={1}", key, parameters[key]);
                        }
                        else
                        {
                            buffer.AppendFormat("{0}={1}", key, parameters[key]);
                            i++;
                        }
                    }
                    byte[] data = Encoding.ASCII.GetBytes(buffer.ToString());
                    using (Stream stream = request.GetRequestStream())
                    {
                        stream.Write(data, 0, data.Length);
                    }
                }
                string[] values = request.Headers.GetValues("Content-Type");
                return request.GetResponse() as HttpWebResponse;
            }

            /// <summary>
            /// 获取请求的数据
            /// </summary>
            public static string GetResponseString(HttpWebResponse webresponse)
            {
                using (Stream s = webresponse.GetResponseStream())
                {
                    StreamReader reader = new StreamReader(s, Encoding.UTF8);
                    return reader.ReadToEnd();
                }
            }

            /// <summary>
            /// 验证证书
            /// </summary>
            private static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
            {
                if (errors == SslPolicyErrors.None)
                    return true;
                return false;
            }
        }



    }
}
