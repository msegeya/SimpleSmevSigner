using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SiuUtils.SignerBase
{
    public class CertMan
    {   
        public static bool CheckSelection()
        {
            return PickCertificate().Verify();
        }
        
        public static X509Certificate2 PickCertificate()
        {           
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            var collection = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
            var gostOnlyCollection = new X509Certificate2Collection();
            
            foreach ( var cert in collection.Cast<X509Certificate2>()
                        .Where(cert => cert.SignatureAlgorithm.Value.Equals("1.2.643.2.2.3")))
                gostOnlyCollection.Add(cert);

            if (gostOnlyCollection.Count == 0)
                throw new ApplicationException("Не найдено ни одной подписи соответствующей ГОСТ Р 34.11/34.10-2001. \n");

            var found = X509Certificate2UI.SelectFromCollection(
                    gostOnlyCollection, 
                    "Выберите сертификат", 
                    "Выбранная ЭЦП будет использована при подписании файла, и является эквивалентом собственноручной подписи либо печати организации", 
                    X509SelectionFlag.SingleSelection
                );

            if (found.Count == 0)
            {
                throw new ApplicationException("Сертификат не выбран.\n");
            }

            if (found.Count > 1)
            {
                throw new ApplicationException("Найдено больше одного сертификата.\n");
            }           

            return found[0];
        }

    }
}
