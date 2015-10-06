using System;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace SiuUtils.SignerBase
{
    public class Signer
    {
        public const int Epov = 0;

        public const int Epsp = 1;

        public static XmlDocument Sign(XmlDocument docToApply, int sigType)
        {
            var cert = CertMan.PickCertificate(); 
            XmlDocument smevPreparedDoc;
            String partition;

            switch (sigType)
            {                    
                case Epov:
                    smevPreparedDoc = 
                        SmevSignedXml.InsertSecurityFromTemplate(
                            SmevSignedXml.CheckBodyId(
                                SmevSignedXml.CheckEnvNamespaces(docToApply)
                            )
                        );
                    partition = SmevSignedXml.GetBodyId(smevPreparedDoc);

                    if (String.IsNullOrWhiteSpace(partition))
                    {
                        throw new ApplicationException("Не удалось найти тело для подписания <Body/> помеченое - wsu:Id");
                    }
                    return ApplySignatureEpov(smevPreparedDoc, cert, partition);

                case Epsp:                    
                    smevPreparedDoc = SmevSignedXml.CheckAppDataId(docToApply);
                    partition = SmevSignedXml.GetAppDataId(smevPreparedDoc);

                    if (String.IsNullOrWhiteSpace(partition))
                    {
                        throw new ApplicationException("Не удалось найти участок для подписания <AppData/> c пометкой Id");
                    }
                    return ApplySignatureEpsp(smevPreparedDoc, cert, partition);
            }
            throw new ApplicationException("Ничего не подписано.");
        }       

        private static XmlDocument ApplySignatureEpov(XmlDocument docToApply, X509Certificate2 cert, String partitionToSign)
        {
            var signedXml = new SmevSignedXml(docToApply) { SigningKey = cert.PrivateKey };

            signedXml.SignedInfo.CanonicalizationMethod = SmevSignedXml.CanonMethodUrl;
            signedXml.SignedInfo.SignatureMethod = SmevSignedXml.SignatureMethodUrl;

            var reference = new Reference {Uri = "#" + partitionToSign, DigestMethod = SmevSignedXml.DigestMethodUrl};
            reference.AddTransform(new XmlDsigExcC14NTransform());             
            signedXml.AddReference(reference);

            try
            {
                signedXml.ComputeSignature();
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Не установлен КриптоПро CSP. \n", ex);                    
            }
                
            var xmlDigitalSignature = signedXml.GetXml();

            docToApply.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0].PrependChild(
                docToApply.ImportNode(xmlDigitalSignature.GetElementsByTagName("SignatureValue")[0], true));
            docToApply.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0].PrependChild(
                docToApply.ImportNode(xmlDigitalSignature.GetElementsByTagName("SignedInfo")[0], true));

            docToApply.GetElementsByTagName("BinarySecurityToken", SmevSignedXml.WsSecurityWsseNamespaceUrl)[0].InnerText = 
                Convert.ToBase64String(cert.RawData);

            return docToApply; 
        }

        public static Boolean VerifyEpovInFile(XmlDocument docToCheck)
        {
            var signedXml = new SmevSignedXml(docToCheck);
            var nodeList = docToCheck.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
            signedXml.LoadXml((XmlElement)nodeList[0]);  

            var referenceList = docToCheck.GetElementsByTagName("Reference", SmevSignedXml.WsSecurityWsseNamespaceUrl);
            if (referenceList.Count == 0)
            {
                throw new XmlException("Не удалось найти указатель подписи \n");
            }

            var binaryTokenReference = ((XmlElement)referenceList[0]).GetAttribute("URI");
            if (string.IsNullOrEmpty(binaryTokenReference) || binaryTokenReference[0] != '#')
            {
                throw new XmlException("Не удалось найти ссылку на сертификат \n");
            }
 
            var binaryTokenElement = signedXml.GetIdElement(docToCheck, binaryTokenReference.Substring(1));
            if (binaryTokenElement == null)
            {
                throw new XmlException("Не удалось найти сертификат \n");
            }

            var cert = new X509Certificate2(Convert.FromBase64String(binaryTokenElement.InnerText));
            return signedXml.CheckSignature(cert.PublicKey.Key);
        }

        private static XmlDocument ApplySignatureEpsp(XmlDocument docToApply, X509Certificate2 cert, String partitionToSign)
        {
            var appData = docToApply.GetElementsByTagName("AppData", SmevSignedXml.SmevNamespaceUrl)[0] as XmlElement;
            if (appData == null)
            {
                throw new ApplicationException("Не найдена AppData.");
            }

            var signedXml = new SignedXml(appData) { SigningKey = cert.PrivateKey };
            
            signedXml.SignedInfo.CanonicalizationMethod = SmevSignedXml.CanonMethodUrl;
            signedXml.SignedInfo.SignatureMethod = SmevSignedXml.SignatureMethodUrl;

            var reference = new Reference { Uri = "#" + partitionToSign, DigestMethod = SmevSignedXml.DigestMethodUrl };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;

            try
            {
                signedXml.ComputeSignature();
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Не установлен КриптоПро CSP. \n", ex);
            }

            var xmlDigitalSignature = signedXml.GetXml();
            appData.AppendChild(docToApply.ImportNode(xmlDigitalSignature, true));
            
            return docToApply;
        }

        public static Boolean VerifyEpspInFile(XmlDocument docToCheck)
        {
            var appData = docToCheck.GetElementsByTagName("AppData", SmevSignedXml.SmevNamespaceUrl)[0] as XmlElement;
            if (appData == null)
            {
                throw new ApplicationException("Не найдена AppData.");
            }

            var signedXml = new SignedXml(appData);

            var nodeList = appData.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

            signedXml.LoadXml((XmlElement)nodeList[0]);

            var referenceList = appData.GetElementsByTagName("Reference");

            if (referenceList.Count == 0)
            {
                throw new XmlException("Не удалось найти указатель подписи \n");
            }

            var link = ((XmlElement)referenceList[0]).GetAttribute("URI");

            if (string.IsNullOrWhiteSpace(link) || link[0] != '#' || '#' + appData.Attributes.GetNamedItem("Id").Value != link)
            {
                throw new XmlException("Не удалось найти ссылку на сертификат, или ссылка не совпадает c указанной в AppData ID \n");
            }

            var binaryKey = ((XmlElement)nodeList[0]).GetElementsByTagName("X509Certificate")[0].InnerText;

            if (string.IsNullOrWhiteSpace(binaryKey))
            {
                throw new XmlException("Не удалось найти сертификат \n");
            }

            var cert = new X509Certificate2(Convert.FromBase64String(binaryKey));
            return signedXml.CheckSignature(cert.PublicKey.Key);
            
        }

        public static String CheckFileSignature(ContentInfo content, byte[] signature)
        {
            var verifyCms = new SignedCms(content, true);
            verifyCms.Decode(signature);

            var cert = verifyCms.SignerInfos[0].Certificate;

            try
            {
                verifyCms.CheckSignature(new X509Certificate2Collection(cert), false);
                return @"Signature is valid";
            }
            catch (CryptographicException)
            {
                return @"Signature is not valid for content";
            }
        }

    }
}
