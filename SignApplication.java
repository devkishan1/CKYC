package com.sign.sign;

import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

@RestController
@SpringBootApplication
@RequestMapping("/api")
public class SignApplication {

    @PostMapping("/sign-pdf")
    public ResponseEntity<byte[]> signPdf(
            @RequestParam("pin") String pin,
            @RequestParam("reason") String reason,
            @RequestParam("location") String locationdata,
            @RequestParam("rectangleX") float rectangleX,
            @RequestParam("rectangleY") float rectangleY,
            @RequestParam("rectangleWidth") float rectangleWidth,
            @RequestParam("rectangleHeight") float rectangleHeight,
            @RequestBody MultipartFile pdfFile) {
        try {
            KeyStore keyStore = initializeKeyStore(pin);
            initializeProvider();

            PrivateKey privateKey = null;
            PublicKey publicKey = null;
            Certificate cert = null;
            X509Certificate x509Certificate = null;

            java.util.Enumeration<String> aliases = keyStore.aliases();
            String alias = null;

            while (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
                cert = keyStore.getCertificate(alias);
                x509Certificate = (X509Certificate) cert;

                if (x509Certificate.getKeyUsage()[0]) {
                    Key key = keyStore.getKey(alias, null);
                    privateKey = (PrivateKey) key;
                    publicKey = x509Certificate.getPublicKey();
                    break;
                }
            }

            ByteArrayInputStream pdfInputStream = new ByteArrayInputStream(pdfFile.getBytes());
            ByteArrayOutputStream signedPdfStream = new ByteArrayOutputStream();

            PdfReader pdfReader = new PdfReader(pdfInputStream);
            PdfStamper pdfStamper = PdfStamper.createSignature(pdfReader, signedPdfStream, '\0');
            PdfSignatureAppearance sap = pdfStamper.getSignatureAppearance();
            sap.setVisibleSignature(new com.itextpdf.text.Rectangle(rectangleX, rectangleY, rectangleWidth, rectangleHeight), 1, "signature");
            sap.setReason(reason);
            sap.setLocation(locationdata);
            ExternalSignature es = new PrivateKeySignature(privateKey, "SHA-1", "SunPKCS11-HYP2003");
            ExternalDigest digest = new BouncyCastleDigest();
            Certificate[] certs = new Certificate[1];
            certs[0] = cert;

            MakeSignature.signDetached(sap, digest, es, certs, null, null, null, 0, MakeSignature.CryptoStandard.CMS);

            byte[] signedPdfBytes = signedPdfStream.toByteArray();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "signed.pdf");
            pdfStamper.close();
            pdfReader.close();

            return new ResponseEntity<>(signedPdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return new ResponseEntity<>("Spring Boot is up and running!", HttpStatus.OK);
    }

    @GetMapping("/checktoken")
    public ResponseEntity<String> checkToken() {
        try {
            initializeProvider();
            KeyStore keyStore = initializeKeyStore("default-pin"); // Use a default pin for checking token

            return new ResponseEntity<>(keyStore.getProvider().toString(), HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("An error occurred while checking the USB token.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(SignApplication.class, args);
    }

    private KeyStore initializeKeyStore(String pin) throws Exception {
        Provider provider = Security.getProvider("SunPKCS11");
        provider = provider.configure("pkcs11.cfg");
        Security.addProvider(provider);
System.out.println(provider.getName());
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        char[] pinCharArray = pin.toCharArray();
        keyStore.load(null, pinCharArray);

        return keyStore;
    }

    private void initializeProvider() throws Exception {
        Provider provider = Security.getProvider("SunPKCS11");
        if (provider == null) {
            throw new RuntimeException("PKCS11 provider not available. USB token not connected.");
        }

        provider = provider.configure("pkcs11.cfg");
        Security.addProvider(provider);
    }
}
