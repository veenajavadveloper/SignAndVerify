import { expect } from "chai";
import crypto from "crypto";
import fs from "fs";
import { signFile, verifyFile } from "../src/index.ts";

describe("RSA File Sign & Verify", () => {

  const privateKeyPath = "private.pem";
  const publicKeyPath = "public.pem";
  const filePath = "message.txt";

  before(() => {

    // 1️⃣ Generate RSA key pair
    const { publicKey, privateKey } =
      crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
      });

    // 2️⃣ Save keys to files
    fs.writeFileSync(
      privateKeyPath,
      privateKey.export({
        type: "pkcs8",
        format: "pem"
      })
    );

    fs.writeFileSync(
      publicKeyPath,
      publicKey.export({
        type: "spki",
        format: "pem"
      })
    );

    // 3️⃣ Create test file
    fs.writeFileSync(filePath, "file to sign and verify");

  });

  it("should sign and verify file correctly", () => {

    const signature = signFile(
      filePath,
      privateKeyPath
    );

    const isValid = verifyFile(
      filePath,
      signature,
      publicKeyPath
    );

    expect(isValid).to.equal(true);

  });

  it("should fail verification if file is tampered", () => {

    const signature = signFile(
      filePath,
      privateKeyPath
    );

    // Tamper file
    fs.writeFileSync(filePath, "Hacked message");

    const isValid = verifyFile(
      filePath,
      signature,
      publicKeyPath
    );

    expect(isValid).to.equal(false);

  });

  after(() => {

    [privateKeyPath, publicKeyPath, filePath].forEach(file => {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    });

  });

});