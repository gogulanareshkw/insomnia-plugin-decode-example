const Rijndael = require("rijndael-js");
const crypto = require("crypto");

const decryptResult = (keytoDecrypt, iv, response, index) => {
  var shasum = crypto.createHash("sha256");
  shasum.update(keytoDecrypt);
  const key = shasum.digest();
  const responseBuffer = Buffer.from(response, "base64");

  const decipher = new Rijndael(key, "cbc");
  const decrypted = decipher.decrypt(responseBuffer, 16, iv);
  const utf8Decrypted = Buffer.from(decrypted);
  console.warn(`Decrypting result # ${index + 1}`);
  var jsonCleaned = utf8Decrypted.toString("utf8");
  return JSON.parse(
    jsonCleaned.replace(
      /[^A-Za-z 0-9 \.,\?""!@#\$%\^&\*\(\)-_=\+;:<>\/\\\|\}\{\[\]`~]*/g,
      ""
    )
  );
};

module.exports.responseHooks = [
  ({ request, response }) => {
    const requestUrl = request.getUrl();

    if (!requestUrl.endsWith("PostAllPortalQueuePull")) return;

    const { all } = request.getEnvironmentVariable("smartware");

    const { api_key, base_url } = all;

    if (!requestUrl.startsWith(base_url)) return;

    const bodyBuffer = response.getBody();
    if (bodyBuffer === null) {
      log("No body in the response to validate");
      return;
    }

    const jsonParsed = JSON.parse(bodyBuffer);
    const { ResultCollection } = jsonParsed;

    if (!Array.isArray(ResultCollection) || !ResultCollection.length) return;

    const now = new Date();
    const isoDate = now.toISOString();
    const today = `${isoDate.substr(0, 4)}${isoDate.substr(
      5,
      2
    )}${isoDate.substr(8, 2)}`;
    const keytoDecrypt = Buffer.from(`${api_key}${today}`, "ascii");
    const iv = Buffer.from(`${today}${today}`, "ascii");
    var results = ResultCollection.map((result, idx) =>
      decryptResult(keytoDecrypt, iv, result, idx)
    );

    jsonParsed.ResultCollection = results;
    response.setBody(JSON.stringify(jsonParsed));
    return;
  },
];
