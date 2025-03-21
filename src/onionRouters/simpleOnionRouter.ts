import bodyParser from "body-parser";
import express from "express";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, exportSymKey, importSymKey, rsaDecrypt, symDecrypt } from "../crypto";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { log } from "console";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  const keyPair = await generateRsaKeyPair();
  

  // Register the node with the registry
  const registryUrl = `http://localhost:${REGISTRY_PORT}/registerNode`;
  const response = await fetch(registryUrl, {
    method: "POST",
    body: JSON.stringify({
      nodeId,
      pubKey: await exportPubKey(keyPair.publicKey),
    }),
    headers: {
      "Content-Type": "application/json",
    },
  });

  var lastReceivedEncryptedMessage: string | null = null;
  var lastReceivedDecryptedMessage: string | null = null;
  var lastMessageDestination: number | null = null;

  // GET /status
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // GET /getLastReceivedEncryptedMessage
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // GET /getLastReceivedDecryptedMessage
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // GET /getLastMessageDestination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // GET /getPrivateKey
  onionRouter.get("/getPrivateKey", (req, res) => {
    // Returns the private key in base64 format
    exportPrvKey(keyPair.privateKey).then((result) => {
      res.json({ result });
    });
  });

  // POST /message
  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body;

    lastReceivedEncryptedMessage = message;

    // Encrypted key is the first 344 characters
    const encryptedSymmetricKey = message.slice(0, 344);
    const encryptedDestinationAndMessage = message.slice(344);

    // Decrypt the symmetric key
    const symmetricKey = await rsaDecrypt(encryptedSymmetricKey, keyPair.privateKey);

    // Decrypt the destination and message
    const destinationAndMessage = await symDecrypt(symmetricKey, encryptedDestinationAndMessage);

    // Split the destination and message
    const destination = parseInt(destinationAndMessage.slice(0, 10));
    const decryptedMessage = destinationAndMessage.slice(10);

    lastMessageDestination = destination;
    lastReceivedDecryptedMessage = decryptedMessage;


    // Make POST request to localhost:${destination}/message
    await fetch(`http://localhost:${destination}/message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: decryptedMessage }),
    });

    res.send("success");
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}