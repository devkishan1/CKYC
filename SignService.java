// SignService.java
package com.sign.sign;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.springframework.stereotype.Service;

@Service
public class SignService {

    public byte[] signPdf(byte[] pdfBytes) {
        try {
            // Replace the following lines with your logic to obtain the private key and certificate from the hardware token
            Provider provider = Security.getProvider("SunPKCS11");
            provider = provider.configure("pkcs11.cfg");
            Security.addProvider(provider);

            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, "12345678".toCharArray());

            Enumeration<String> aliases = keyStore.aliases();
            String alias = null;

            while (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);

                if (cert != null && cert instanceof java.security.cert.X509Certificate) {
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
                    byte[] signedPdf = signPdfWithSignature(pdfBytes, privateKey, (java.security.cert.X509Certificate) cert,provider.getName());
                    return signedPdf;
                }
            }

            throw new RuntimeException("No suitable private key found in the hardware token.");
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error signing PDF");
        }
    }

    private byte[] signPdfWithSignature(byte[] pdfBytes, PrivateKey privateKey,
            java.security.cert.X509Certificate cert, String string) throws IOException, DocumentException, GeneralSecurityException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            PdfReader pdfReader = new PdfReader(pdfBytes);
            PdfStamper stamper = PdfStamper.createSignature(pdfReader, baos, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason("Author Abdullah AlHussein");
            appearance.setLocation("Riyadh Saudi Arabia");
            appearance.setVisibleSignature(new com.itextpdf.text.Rectangle(36, 748, 144, 780), 1, "signature");

		    ExternalSignature es = new PrivateKeySignature(privateKey, "SHA-1", string);
            ExternalDigest digest = new BouncyCastleDigest();

            MakeSignature.signDetached(appearance, digest, es, new Certificate[] { cert }, null, null, null, 0,
                    CryptoStandard.CMS);

            return baos.toByteArray();
        }
    }
}
