using System;
using System.Xml;
using System.Security.Cryptography.Xml;

namespace SiuUtils.SignerBase
{   
    class SmevSignedXml : SignedXml
    {
        public const string CanonMethodUrl = @"http://www.w3.org/2001/10/xml-exc-c14n#";

        public const string SignatureMethodUrl = @"http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

        public const string DigestMethodUrl = @"http://www.w3.org/2001/04/xmldsig-more#gostr3411";

        public const string ActorNamespaceUrl = @"http://smev.gosuslugi.ru/actors/smev";

        public const string SmevNamespaceUrl = @"http://smev.gosuslugi.ru/rev120315";

        public const string SmevNamespaceUrlOld = @"http://smev.gosuslugi.ru/rev111111";

        public const string EnvNamespaceUrl = @"http://schemas.xmlsoap.org/soap/envelope/";

        public const string W3DigSigNamespaceUrl = @"http://www.w3.org/2000/09/xmldsig#";

        public const string WsSecurityWsseNamespaceUrl =
            @"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        public const string WsSecurityWsuNamespaceUrl =
            @"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        public const string WsSecurityBtNamespaceUrl =
            @"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

        public const string WsSecurity509V3NamespaceUrl =
            @"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

        public SmevSignedXml(XmlDocument document) : base(document) { }
  
        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            var nsmgr = new XmlNamespaceManager(document.NameTable);
            nsmgr.AddNamespace("wsu", WsSecurityWsuNamespaceUrl);
            return document.SelectSingleNode(String.Format("//*[@wsu:Id='{0}']", idValue), nsmgr) as XmlElement;
        }

        public static XmlDocument InsertSecurityFromTemplate(XmlDocument inp)
        {
            var env = inp.GetElementsByTagName("Envelope", EnvNamespaceUrl)[0];
            var head = inp.GetElementsByTagName("Header", EnvNamespaceUrl)[0];

            var sec = inp.CreateElement(env.GetPrefixOfNamespace(WsSecurityWsseNamespaceUrl), "Security", WsSecurityWsseNamespaceUrl);
            sec.SetAttribute("actor", EnvNamespaceUrl, ActorNamespaceUrl);

            var bt = inp.CreateElement(env.GetPrefixOfNamespace(WsSecurityWsseNamespaceUrl), "BinarySecurityToken", WsSecurityWsseNamespaceUrl);
            bt.SetAttribute("EncodingType", WsSecurityBtNamespaceUrl);
            bt.SetAttribute("ValueType", WsSecurity509V3NamespaceUrl);
            bt.SetAttribute("Id", WsSecurityWsuNamespaceUrl, "CertId");

            sec.AppendChild(bt);

            var sig = inp.CreateElement(env.GetPrefixOfNamespace(W3DigSigNamespaceUrl), "Signature", W3DigSigNamespaceUrl);

            var ki = inp.CreateElement(env.GetPrefixOfNamespace(W3DigSigNamespaceUrl), "KeyInfo", W3DigSigNamespaceUrl);

            var stRef = inp.CreateElement(env.GetPrefixOfNamespace(WsSecurityWsseNamespaceUrl), "SecurityTokenReference", WsSecurityWsseNamespaceUrl);

            var Ref = inp.CreateElement(env.GetPrefixOfNamespace(WsSecurityWsseNamespaceUrl), "Reference", WsSecurityWsseNamespaceUrl);
            Ref.SetAttribute("URI", "#CertId");
            Ref.SetAttribute("ValueType", WsSecurity509V3NamespaceUrl);

            stRef.AppendChild(Ref);
            ki.AppendChild(stRef);
            sig.AppendChild(ki);

            sec.AppendChild(sig);

            head.AppendChild(sec);
            return inp;
        }

        public static XmlDocument CheckEnvNamespaces(XmlDocument inp)
        {
            var attrs = inp.GetElementsByTagName("Envelope", EnvNamespaceUrl)[0].Attributes;

            if (attrs != null && attrs.GetNamedItem("xmlns:wsse") == null)
            {
                var wsse = inp.CreateAttribute("xmlns:wsse");
                wsse.Value = WsSecurityWsseNamespaceUrl;
                attrs.Append(wsse);
            }

            if (attrs != null && attrs.GetNamedItem("xmlns:wsu") == null)
            {
                var wsu = inp.CreateAttribute("xmlns:wsu");
                wsu.Value = WsSecurityWsuNamespaceUrl;
                attrs.Append(wsu);
            }

            if (attrs != null && attrs.GetNamedItem("xmlns:ds") == null)
            {
                var ds = inp.CreateAttribute("xmlns:ds");
                ds.Value = W3DigSigNamespaceUrl;
                attrs.Append(ds);
            }    

            if (inp.FirstChild is XmlDeclaration)
            {
                inp.RemoveChild(inp.FirstChild);
            }

            return inp;
        }

        public static XmlDocument CheckBodyId(XmlDocument inp)
        {
            var attrs = inp.GetElementsByTagName("Body", EnvNamespaceUrl)[0].Attributes;

            if (attrs == null || attrs.GetNamedItem("wsu:Id") != null) return inp;
            var wsid = inp.CreateAttribute("Id", WsSecurityWsuNamespaceUrl);
            wsid.Value = "body";
            attrs.Append(wsid);
            return inp;
        }

        public static String GetBodyId(XmlDocument inp)
        {
            var attrs = inp.GetElementsByTagName("Body", EnvNamespaceUrl)[0].Attributes;
            return attrs != null ? attrs.GetNamedItem("Id", WsSecurityWsuNamespaceUrl).Value : null;
        }

        public static String GetIdByTag(XmlElement inp)
        {
            return inp.Attributes.GetNamedItem("Id").Value;
        }

        public static XmlDocument CheckAppDataId(XmlDocument inp)
        {
            var attrs = inp.GetElementsByTagName("AppData", SmevNamespaceUrl)[0].Attributes;

            if (attrs == null || attrs.GetNamedItem("Id") != null) return inp;
            var adid = inp.CreateAttribute("Id");
            adid.Value = "_AppData";
            attrs.Append(adid);
            return inp;
        }

        public static String GetAppDataId(XmlDocument inp)
        {
            var attrs = inp.GetElementsByTagName("AppData", SmevNamespaceUrl)[0].Attributes;
            return attrs != null ? attrs.GetNamedItem("Id").Value : null;
        }
    }
}
