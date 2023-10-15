const { create } = require('xmlbuilder2');
const crypto = require('crypto');
const fs = require('fs');
const { spawn } = require('child_process');


const root = create({ version: '1.0', encoding: 'UTF-8', standalone: 'yes' })
  .ele('PID_DATA')
    .ele('DATE_TIME').txt('20-05-2021 17:15:57').up()
    .ele('ID_NO').txt('D4567890').up()
    .ele('ID_TYPE').txt('A').up()
  .up();

// convert the XML tree to string
const xml = root.end({ prettyPrint: true });
console.log(xml);

const dataToEncrypt = Buffer.from(xml);

// Generate a random 256-bit session key (32 bytes)
const sessionKey = crypto.randomBytes(32);

// Generate a random initialization vector (IV) for AES (16 bytes)
const iv = crypto.randomBytes(16);

// Create an AES cipher with the session key and IV
const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, iv);

// Encrypt the data
let encryptedData = cipher.update(dataToEncrypt);
encryptedData = Buffer.concat([encryptedData, cipher.final()]);

console.log('Encrypted Data (Base64):', encryptedData.toString('base64'));
let encryptedPID =encryptedData.toString('base64')

const certData = fs.readFileSync('server_pub.cer'); // Read the public key file
const cert = new crypto.X509Certificate(certData);

// Your session key as a Buffer

// Encrypt the session key using the public key from the certificate
const encryptedSessionKey = crypto.publicEncrypt(cert.publicKey, sessionKey);

console.log('Encrypted Session Key (Base64):', encryptedSessionKey.toString('base64'));

const root2 = create({ version: '1.0', encoding: 'UTF-8' })
  .ele('REQ_ROOT')
    .ele('HEADER')
      .ele('FI_CODE').txt('IN1895').up()
      .ele('REQUEST_ID').txt('02').up()
      .ele('VERSION').txt('1.2').up()
    .up()
    .ele('CKYC_INQ')
      .ele('PID').txt(encryptedPID).up()
      .ele('SESSION_KEY').txt(encryptedSessionKey.toString('base64')).up()
    .up()
  .up();

// Convert the XML tree to a string
const xml2 = root2.end({ prettyPrint: true });
console.log(xml2);
