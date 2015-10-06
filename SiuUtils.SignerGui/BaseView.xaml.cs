using System.Security.Cryptography.Pkcs;
using Microsoft.Win32;

using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Windows;
using System.Windows.Controls;

using SiuUtils.SignerBase;


namespace SiuUtils.SignerGui
{
    public partial class BaseView : IDisposable
    {
        private String _currentFilename = String.Empty;

        public void Dispose()
        {
            //
        }

        public BaseView()
        {
            InitializeComponent();
            LogTBox.Clear();
        }

        private XmlDocument OpenXml()
        {
            var fileDialog = new OpenFileDialog { Filter = "XML Files(*.*)|*.XML", Multiselect = false };
            if (!fileDialog.ShowDialog().GetValueOrDefault()) return null;
            _currentFilename = fileDialog.FileName;
            var doc = new XmlDocument();
            var xmltr = new XmlTextReader(_currentFilename);
            doc.Load(xmltr);
            xmltr.Close();

            LogTBox.AppendText(String.Format("XML ready\n{0}\n", _currentFilename));
            return doc;
        }

        private void VerifyCertClk(object sender, RoutedEventArgs e)
        {
            try
            {
                LogTBox.AppendText(CertMan.CheckSelection() ? String.Format("Verification success\n") 
                    : String.Format("Verification fails\n"));
            }
            catch (Exception ex)
            {
                LogTBox.AppendText(String.Format("Exception:\n{0}\n", Helper.ExceptionToXml(ex).InnerText));
            }
        }

        private void VerifyDetachedClk(object sender, RoutedEventArgs e)
        {
            try
            {
                ContentInfo content = null;
                var fileDialog = new OpenFileDialog { Title = @"Файл данных", Filter = "Data Files(*.*)|*.*", Multiselect = false };
                if (fileDialog.ShowDialog().GetValueOrDefault())
                {
                    content = new ContentInfo(File.ReadAllBytes(fileDialog.FileName));
                }

                byte[] signature = null;
                var sigDialog = new OpenFileDialog { Title = @"Файл подписи", Filter = "SIG Files(*.*)|*.sig", Multiselect = false };
                if (sigDialog.ShowDialog().GetValueOrDefault())
                {
                    signature = File.ReadAllBytes(sigDialog.FileName);
                }

                if ((content != null) && (signature != null))
                {
                    LogTBox.AppendText(String.Format("Verification result :\n{0}\n", Signer.CheckFileSignature(content, signature)));
                }
            }
            catch (Exception ex)
            {
                LogTBox.AppendText(String.Format("Exception:\n{0}\n", Helper.ExceptionToXml(ex).InnerText));
            }
        }

        private void SignOvClk(object sender, RoutedEventArgs e)
        {
            SignByType(Signer.Epov);
        }

        private void SignSpClk(object sender, RoutedEventArgs e)
        {
            SignByType(Signer.Epsp);
        }

        /// <summary>
        /// Sign Xml in SMEV-Style
        /// </summary>
        private void SignByType(int sType)
        {
            try
            {
                var doc = Signer.Sign(OpenXml(), sType);
                var signedFilename = _currentFilename.Replace(".xml", ".signed.xml");
                var xmltw = new XmlTextWriter(signedFilename, new UTF8Encoding(false)) { Formatting = Formatting.None };
                doc.WriteTo(xmltw);
                xmltw.Close();

                LogTBox.AppendText(String.Format("Successfully signed\n{0}\n", signedFilename));
            }
            catch (Exception ex)
            {
                LogTBox.AppendText(String.Format("Exception:\n{0}\n", Helper.ExceptionToXml(ex).InnerText));
            }
        }

        /// <summary>
        /// Check OV signature in SMEV-Style signed Xml
        /// </summary>
        private void CheckOvClk(object sender, RoutedEventArgs e)
        {
            try
            {
                var doc = OpenXml();
                LogTBox.AppendText(Signer.VerifyEpovInFile(doc) ? "Signature is valid\n" : "Invalid signature\n"); 
            }
            catch (Exception ex)
            {
                LogTBox.AppendText("Exception: \n" + Helper.ExceptionToXml(ex).InnerText);
            }
        }

        /// <summary>
        /// Check SP signature in SMEV-Style signed Xml
        /// </summary>
        private void CheckSpClk(object sender, RoutedEventArgs e)
        {
            try
            {
                XmlDocument doc = OpenXml();
                LogTBox.AppendText(Signer.VerifyEpspInFile(doc) ? "Signature is valid\n" : "Invalid signature\n");
            }
            catch (Exception ex)
            {
                LogTBox.AppendText("Exception: \n" + Helper.ExceptionToXml(ex).InnerText);
            }
            
        }

        private void IndentClk(object sender, RoutedEventArgs e)
        {
            try
            {
                var doc = OpenXml();
                var xmltw = new XmlTextWriter(_currentFilename, new UTF8Encoding(false)) { Formatting = Formatting.Indented };
                doc.WriteTo(xmltw);
                xmltw.Close();                
            }
            catch (Exception ex)
            {
                LogTBox.AppendText(String.Format("Exception:\n{0}\n", Helper.ExceptionToXml(ex).InnerText));
            }  
        }

        private void UnindentClk(object sender, RoutedEventArgs e)
        {
            try
            {
                var doc = OpenXml();
                var xmltw = new XmlTextWriter(_currentFilename, new UTF8Encoding(false)) { Formatting = Formatting.None };
                doc.WriteTo(xmltw);
                xmltw.Close();
            }
            catch (Exception ex)
            {
                LogTBox.AppendText(String.Format("Exception:\n{0}\n", Helper.ExceptionToXml(ex).InnerText));
            }
        }

        private void GetZipClk(object sender, RoutedEventArgs e)
        {
            try
            {
                Helper.GetZipFromXml(OpenXml(), _currentFilename);
            }
            catch (Exception ex)
            {
                LogTBox.AppendText(String.Format("Exception:\n{0}\n", Helper.ExceptionToXml(ex).InnerText));
            }
        }

        private void OnConsoleTextChanged(object sender, TextChangedEventArgs e)
        {
            LogTBox.ScrollToEnd();
        }

        private void OnSwitchPanelLayoutChanged(object sender, RoutedEventArgs e)
        {
            //
        }

         
    }
}
