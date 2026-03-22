import crypto from "crypto";
import fs from "fs";

/**
 * Sign a file using private key
 */
export function signFile(
  filePath: string,
  privateKeyPath: string
): Buffer {

  const data = fs.readFileSync(filePath);

  const privateKey = fs.readFileSync(privateKeyPath, "utf8");

  const signer = crypto.createSign("sha256");

  signer.update(data);
  signer.end();

  return signer.sign(privateKey);
}

/**
 * Verify a file using public key
 */
export function verifyFile(
  filePath: string,
  signature: Buffer,
  publicKeyPath: string
): boolean {

  const data = fs.readFileSync(filePath);

  const publicKey = fs.readFileSync(publicKeyPath, "utf8");

  const verifier = crypto.createVerify("sha256");

  verifier.update(data);
  verifier.end();

  return verifier.verify(publicKey, signature);
}