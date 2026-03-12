const test = require("node:test");
const assert = require("node:assert/strict");
const { once } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");

// Load test env vars from Echo-backend/.env.test (preferred) or Echo-backend/.env
// This keeps secrets out of your shell history and avoids long PowerShell commands.
const dotenv = require("dotenv");
const envTestPath = path.join(__dirname, "..", ".env.test");
const envPath = path.join(__dirname, "..", ".env");
dotenv.config({ path: fs.existsSync(envTestPath) ? envTestPath : envPath });

// Prefer an explicit test DB so you don't pollute your real DB.
// Set this before importing server.js because it connects at import time.
if (process.env.MONGO_URI_TEST) {
  process.env.MONGO_URI = process.env.MONGO_URI_TEST;
}

if (!process.env.MONGO_URI) {
  throw new Error(
    "Missing MONGO_URI. Set MONGO_URI_TEST (recommended) or MONGO_URI before running tests."
  );
}

// Avoid crashes if JWT_SECRET isn't set in test env
process.env.JWT_SECRET = process.env.JWT_SECRET || "test-secret";

const ioClient = require("socket.io-client");
const jwt = require("jsonwebtoken");
const { server, mongoose, Message, User } = require("../server");

async function waitForMongo() {
  if (mongoose.connection.readyState === 1) return;
  await once(mongoose.connection, "connected");
}

test("newMessage persists sendingNumber and previousSendingNumber", async () => {
  await waitForMongo();

  // Start server on an ephemeral port for the test
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const userId = "TESTU1";
  const targetUserId = "TESTU2";
  const payload = `cipher-${Date.now()}`;

  let client = null;
  try {
    // The server's newMessage handler requires the sender to exist
    await User.create({
      id: userId,
      username: `user-${Date.now()}`,
      hashedPassword: "x",
      publicIdentityKeyX25519: "x",
      publicIdentityKeyEd25519: "x",
      signedPreKey: "x",
      signature: "x",
    });

    const token = jwt.sign(
      { id: userId, username: "tester" },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    client = ioClient(`http://localhost:${port}`, {
      transports: ["websocket"],
      auth: { token },
    });

    await once(client, "connect");

    const sendingNumber = 7;
    const previousSendingNumber = 3;

    client.emit("newMessage", {
      is_initial: true,
      payload,
      nonce: "nonce",
      userId,
      targetUserId,
      username: "tester",
      messageNumber: 0,
      publicEphemeralKey: "pubEph",
      sendingNumber,
      previousSendingNumber,
    });

    // Wait until the message appears (poll)
    const deadline = Date.now() + 3000;
    let saved = null;
    while (Date.now() < deadline) {
      // eslint-disable-next-line no-await-in-loop
      saved = await Message.findOne({ userId, targetUserId, payload }).lean();
      if (saved) break;
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 50));
    }

    assert.ok(saved, "expected message to be saved to MongoDB");
    assert.equal(saved.sendingNumber, sendingNumber);
    assert.equal(saved.previousSendingNumber, previousSendingNumber);
  } finally {
    if (client) client.disconnect();
    await Message.deleteMany({ userId, targetUserId, payload });
    await User.deleteMany({ id: userId });
    await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  }
});
