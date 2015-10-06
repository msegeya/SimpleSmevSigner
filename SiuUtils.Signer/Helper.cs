using System;
using System.IO;
using System.Xml;

namespace SiuUtils.SignerBase
{
    public class Helper
    {
        public static void GetZipFromXml(XmlDocument doc, String docPath)
        {
            var elem = doc.GetElementsByTagName("AppDocument", SmevSignedXml.SmevNamespaceUrlOld)[0] as XmlElement ??
                              doc.GetElementsByTagName("AppDocument", SmevSignedXml.SmevNamespaceUrl)[0] as XmlElement;

            if (elem == null) throw new ApplicationException("Не найден зип пакет AppDocument");
            
            var filename = elem.FirstChild.InnerText + ".zip";
            var binary = elem.LastChild.InnerText;

            File.WriteAllBytes(Path.GetDirectoryName(docPath) + "\\" + filename, Convert.FromBase64String(binary));            
        }

        public static XmlDocument ExceptionToXml(Exception inpExc)
        {
            if (inpExc == null) throw new ArgumentNullException("inpExc");
            var doc = new XmlDocument();
            doc.AppendChild(doc.CreateXmlDeclaration("1.0", "UTF-8", null));

            var exc = doc.CreateElement("Exception");
            exc.SetAttribute("Source", inpExc.Source);

            var msg = doc.CreateElement("Message");
            msg.AppendChild(doc.CreateTextNode(inpExc.Message));
            exc.AppendChild(msg);

            var tgt = doc.CreateElement("Target");
            tgt.AppendChild(doc.CreateTextNode(inpExc.TargetSite.ToString()));
            exc.AppendChild(tgt);

            var trc = doc.CreateElement("StackTrace");
            trc.AppendChild(doc.CreateTextNode(inpExc.StackTrace));
            exc.AppendChild(trc);

            doc.AppendChild(exc);
            return doc;
        }        
    }
}
