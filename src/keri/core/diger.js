const {Crymat} = require('./cryMat')
const derivation_code = require('./derivationCode&Length')
const libsodium = require('libsodium-wrappers-sumo')
const blake3 = require('blake3')

/**
 * @description : Diger is subset of Crymat and is used to verify the digest of serialization
 * It uses  .raw : as digest
 * .code as digest algorithm
 * 
 */
class Diger extends Crymat {
  // This constructor will assign digest verification function to ._verify
    constructor(raw = null, ser = null, code = derivation_code.oneCharCode.Blake3_256, qb64 = null) {
    // console.log("inside Diger(extending Crymat) :")
    try {
      // console.log("Diger qb64 ===================+>",code)
      super(raw, qb64, null, code, 0)
        } catch (error) {
                if(!ser) {
        throw new Error(error);
      }
      if (code==derivation_code.oneCharCode.Blake3_256) {
                    const hasher = blake3.createHash();
// let dig = blake3.hash(ser);
        let dig = hasher.update(ser).digest('');
        //  console.log("Diger dig ================>",dig.toString())
        super(dig , null , null, code,0)
      } else {
        throw new Error(`Unsupported code = ${code} for digester.`);
      }
    }

    if(code ==derivation_code.oneCharCode.Blake3_256) {
      // console.log("this._verify -------------->",this._code )

      this._verify = this._blake3_256
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
        // console.log("this.raw  ============>",(this._raw).toString())
        // console.log("SER --------------------_>",ser.toString())
        return this._verify(ser, this.raw());
    }
//     _blake3_256(ser, dig){
//         console.log("INSIDE blake_256 methodd ",blake3.createHash(ser).digest(), '\n\n',dig)
//     return (blake3.createHash(ser).digest() == dig)
//   }

_blake3_256(ser, dig){
//     console.log("value of Ser is -------------_>",ser.toString())
//     console.log("value of dig is -------------_>",dig.toString())
//     let hash  = blake3.createHash(ser)
//       let digest  = hash.digest({ length: 64 })
//       console.log("INSIDE blake_256 methodd ",digest.toString(), '\n\n',dig.toString())
//   return (digest.toString() == dig.toString())


const hasher = blake3.createHash();
// let dig = blake3.hash(ser);
let digest = hasher.update(ser).digest('')
console.log("Digests equal =============================> \n \n",digest.toString(),'\n',dig.toString())
return (digest.toString() == dig.toString())
  }
}


module.exports = {Diger}