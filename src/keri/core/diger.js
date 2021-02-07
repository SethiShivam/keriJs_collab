// const libsodium = require('libsodium-wrappers-sumo');  // Uncomment when needed
const blake3 = require("blake3");
const { Crymat } = require("./cryMat");
const { oneCharCode } = require("./derivationCode&Length");

let dig;
/**
 * @description : Diger is subset of Crymat and is used to verify the digest of serialization
 * It uses  .raw : as digest
 * .code as digest algorithm
 *
 */
class Diger extends Crymat {
  // This constructor will assign digest verification function to ._verify
  constructor(
    raw = null,
    ser = null,
    code = oneCharCode.Blake3_256,
    qb64 = null
  ) {
    try {
      super(raw, qb64, null, code, 0);
    } catch (error) {
      if (!ser) {
        throw error;
      }

      if (code === oneCharCode.Blake3_256) {
        const hasher = blake3.createHash();
        dig = hasher.update(ser).digest("");

        // super(dig, null, null, code, 0);
      } else if (code === oneCharCode.Blake2b_256) {
        const hasher = blake3.createHash("sha2b_256");
        dig = hasher.update(ser).digest(""); // (digest_size = 32)
        // super(dig, null, null, code, 0);
      } else if (code === oneCharCode.Blake2s_256) {
        const hasher = blake3.createHash("sha2s_256");
        dig = hasher.update(ser).digest(""); // (digest_size = 32)
        // super(dig, null, null, code, 0);
      } else {
        throw new Error(`Unsupported code = ${code} for digester.`);
      }
      super(dig, null, null, code, 0);
    }

    if (code === oneCharCode.Blake3_256) {
      this.verifyDig = this.blake3_256;
    } else {
      throw new Error(`Unsupported code = ${code} for digester.`);
    }
  }

  /**
     *
     * @param {bytes} ser  serialization bytes
     * @description  This method will return true if digest of bytes serialization ser matches .raw
     * using .raw as reference digest for ._verify digest algorithm determined
        by .code
     */
  verify(ser) {
    return this.verifyDig(ser, this.getRaw);
  }

  // eslint-disable-next-line no-underscore-dangle
  // eslint-disable-next-line camelcase
  // eslint-disable-next-line class-methods-use-this
  blake3_256(ser, digst) {
    const hasher = blake3.createHash();
    const digest = hasher.update(ser).digest("");
    return digest.toString() === digst.toString();
  }
}
module.exports = { Diger };
