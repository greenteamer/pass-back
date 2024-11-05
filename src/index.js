const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { PKPass } = require("passkit-generator");

const certDirectory = path.resolve(process.cwd(), "src", "cert");
const wwdr = fs.readFileSync(path.join(certDirectory, "wwdr.pem"));
const signerCert = fs.readFileSync(path.join(certDirectory, "signerCert.pem"));
const signerKey = fs.readFileSync(path.join(certDirectory, "signerKey.key"));

const fastify = require("fastify")({
  logger: true,
});

// Declare a route
fastify.get("/", function (request, reply) {
  reply.send({ status: "ok" });
});

fastify.post("/", async (request, reply) => {
  const { name } = request.body;

  // Feel free to use any other kind of UID here or even read an
  // existing ticket from the database and use its ID
  const passID = crypto
    .createHash("md5")
    .update(`${name}_${Date.now()}`)
    .digest("hex");

  // Generate the pass
  const pass = await PKPass.from(
    {
      model: path.resolve(process.cwd(), "src", "ticket.pass"),
      certificates: {
        wwdr,
        signerCert,
        signerKey,
        signerKeyPassphrase: "balabas777",
      },
    },
    {
      eventTicket: {},
      serialNumber: passID,
    },
  );

  // Adding some settings to be written inside pass.json
  pass.setBarcodes(passID);
  if (Boolean(name)) {
    pass.secondaryFields.push({
      key: "name",
      label: "Name",
      value: name,
    });
  }

  reply.header("Content-Type", "application/vnd-apple.pkpass");

  reply.send(pass.getAsBuffer());
});

// Start the server
fastify.listen(
  { port: process.env.PORT ?? 3000, host: "0.0.0.0" },
  function (err) {
    if (err) {
      fastify.log.error(err);
      process.exit(1);
    }
  },
);