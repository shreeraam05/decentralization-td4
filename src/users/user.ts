import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { Node } from "../registry/registry";
import { createRandomSymmetricKey, rsaEncrypt, symEncrypt, exportSymKey } from "../crypto";
import { webcrypto } from "crypto";
import { log } from "console";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

async function generateRandomCircuit() {

  // Get nodes from the registry
  const registryUrl = `http://localhost:${REGISTRY_PORT}/getNodeRegistry`;
  const response = await fetch(registryUrl);
  const { nodes } = await response.json() as { nodes: Node[] };

  // Select 3 random nodes
  const circuit = [] as Node[];
  while (circuit.length < 3) {
    const randomNode = nodes[Math.floor(Math.random() * nodes.length)];
    if (!circuit.includes(randomNode)) {
      circuit.push(randomNode);
      nodes.splice(nodes.indexOf(randomNode), 1);
    }
  }
  return circuit;
}

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit = [] as number[];

  // GET /status
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // GET /getLastReceivedMessage
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // GET /getLastSentMessage
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // GET /getLastCircuit
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // POST /message
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  // POST /sendMessage
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;

    lastSentMessage = message;
  
    // Generate a random circuit of 3 distinct nodes
    const circuit = await generateRandomCircuit() as Node[];
    lastCircuit = circuit.map(node => node.nodeId);

    var paddedDestination = (destinationUserId + BASE_USER_PORT).toString().padStart(10, "0");

    let encryptedMessage = message;
    for (const node of [...circuit].reverse()) {
      const symmetricKey = await createRandomSymmetricKey() as webcrypto.CryptoKey;

      // Encrypt the destination and the message with the symmetric key
      const destinationAndMessageEncrypted = await symEncrypt(symmetricKey, `${paddedDestination}${encryptedMessage}`);

      // Encrypt the symmetric key with the node's public key
      const encryptedSymmetricKey = await rsaEncrypt(await exportSymKey(symmetricKey), node.pubKey);

      // Concatenate the encrypted symmetric key with the encrypted message
      encryptedMessage = `${encryptedSymmetricKey}${destinationAndMessageEncrypted}`;

      paddedDestination = (node.nodeId + BASE_ONION_ROUTER_PORT).toString().padStart(10, "0");
    }
    
    
    // Send the final encrypted message to the entry node's /message route
    const entryNode = circuit[0];
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + entryNode.nodeId}/message`, {
      method: "POST",
      headers: {
      "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: encryptedMessage })
    });
  
    res.send("success");
  });


  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}