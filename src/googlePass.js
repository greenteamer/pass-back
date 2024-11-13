// TODO: Create a new Generic pass for the user
const jose = require("jose");

const issuerEmail =
  "test-service-account@test-wallet-project-440812.iam.gserviceaccount.com";
const issuerId = "3388000000022792284";
const classId = "testwallet_class_id";

const handleGooglePass = async (passId, credentials) => {
  const genericObject = {
    id: `${issuerId}.${passId}`,
    classId: `${issuerId}.${classId}`,
    genericType: "GENERIC_TYPE_UNSPECIFIED",
    cardTitle: {
      defaultValue: {
        language: "en",
        value: "Google I/O '22",
      },
    },
    subheader: {
      defaultValue: {
        language: "en",
        value: "Attendee",
      },
    },
    header: {
      defaultValue: {
        language: "en",
        value: "Alex McJacobs",
      },
    },
  };

  const iat = Math.floor(Date.now() / 1000);

  const claims = {
    iss: issuerEmail,
    aud: "google",
    typ: "savetowallet",
    iat,
    origins: [],
    payload: {
      genericObjects: [genericObject],
    },
  };

  const alg = "RS256";
  const privateKey = await jose.importPKCS8(credentials, alg);
  const token = await new jose.SignJWT(claims)
    .setProtectedHeader({
      alg,
    })
    .sign(privateKey);

  return token;
};

module.exports = {
  handleGooglePass: handleGooglePass,
};
