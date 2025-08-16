// SignController.java
package com.sign.sign;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/sign")
public class SignController {

    private final SignService signService;

    public SignController(SignService signService) {
        this.signService = signService;
    }

    

    @PostMapping("/sign-pdsf")
    public ResponseEntity<byte[]> signPdf(@RequestBody MultipartFile pdfFile) {
        try {
            byte[] signedPdf = signService.signPdf(pdfFile.getBytes());
            return ResponseEntity.ok().body(signedPdf);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().build();
        }
    }
}
