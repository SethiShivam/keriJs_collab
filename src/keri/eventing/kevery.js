


// Kevery processes an incoming message stream and when appropriate generates
// an outgoing steam. When the incoming streams includes key event messages
// then Kevery acts putKes Kever (KERI key event verifier) factory.

const { Serder } = require('../core/serder')
const derivationCodes = require('../core/derivationCode&Length')
const { Prefixer } = require('../core/prefixer')
const { Kever } = require('../eventing/Kever')
const { CryCounter } = require('../core/cryCounter')
const {Sigcounter} = require('../core/SigCounter')
const {Sigver} = require('../core/sigver')
const {Siger} = require('../core/siger')
const { Serials, Versionage, IcpLabels, Ilks } = require('../core/core')
const {SealEvent} = require('../eventing/util')
const _ = require('lodash');
const { range } = require("lodash");
const { Verfer } = require("../core/verfer");
const { snkey, Logger, dgkey } = require('../db/database')
// Only supports current version VERSION

// Has the following public attributes and properties:

// Attributes:
// .ims is bytearray incoming message stream
// .oms is bytearray outgoing message stream
// .kevers is dict of existing kevers indexed by pre (qb64) of each Kever
// .logs is named tuple of logs
// .framed is Boolean stream is packet framed If True Else not framed
class Kevery {


    constructor(ims = null, oms = null, kevers = null, logger = null, framed = true) {

        if (ims) { this.ims = ims } else {
            this.ims =  Buffer.alloc(256);
        }

        if (oms) { this.oms = oms } else {
            this.oms =  Buffer.alloc(256);
        }

        if (framed) { this.framed = true } else {
            this.framed = false
        }

        if (kevers) { this.kevers = kevers } else {
            this.kevers = {}
        }

        if (!logger) { 
            
            this.logger_= new Logger().next().value
            //this.logger = logger_.next().value
        }
        else {
            this.logger = logger
        }

    }


    /**
 * @description  Process all messages from incoming message stream, ims, when provided
Otherwise process all messages from .ims
 */
     async   processAll(ims = null) {
            
        if (ims) {
            console.log("IMS NOT NULL:")
            if (!(ims instanceof Buffer)) {
                ims = Buffer.from(ims,'binary')
            } 
        }else {
            console.log("IMS = NULL")
            ims = this.ims
        }
        let ims_ = [ims]
        console.log("\nims_ ===============================>",ims_.length)

        console.log("PROCESSING INSCEPTION MESSAGES :")
               for (let i = 0 ; i < ims_.length ; i ++) {
                try {
                   
             this.processOne(ims_[i], this.framed)
                } catch (error) {
                    console.log("\nERROR pROCESSING IMS:",error)
                    throw error
                }
            }
        // while(ims_.length){
                // return response
        // }
    }


    /**
     * @description Extract one msg with attached signatures from incoming message stream, ims
    And dispatch processing of message
     * @param {*} ims ims is bytearray of serialized incoming message stream.
                May contain one or more sets each of a serialized message with
                attached cryptographic material such as signatures or receipts.
 
    * @param {*} framed framed is Boolean, If True and no sig counter then extract signatures
                        until end-of-stream. This is useful for framed packets with
                         one event and one set of attached signatures per invocation.
     */
    processOne(ims, framed = true) {
        let serder, nsigs ,counter = null
        let sigers = []
       console.log("\n\nIncoming message sent by controller is : ",ims.toString())
        try {
            console.log("\n\nCALLING SERDER TO SERIALIZE OR DESERIALIZE MESSAGE :")
            serder = new Serder(ims)
            serder.set_raw(ims)
        } catch (err) {
            throw `Error while processing message stream = ${err}`
        }

        let version = serder.version()
        
        if (!_.isEqual(version, Versionage)) {
            throw `Unsupported version = ${version}, expected ${Versionage}.`
        }
        console.log("\nSTRIPPING EVENTS FROM INCOMING MESSAGE")
        ims =  ims.slice(serder.size(),ims.length)
        let ilk = serder.ked()['ilk']  //# dispatch abased on ilk (Types of events)
        console.log("Type of event:",ilk)
        let arr = new Array(Ilks.icp, Ilks.rot, Ilks.ixn, Ilks.dip, Ilks.drt)
        if (arr.includes(ilk)) {

            try {
                console.log('\n\nEXTRACTING SIGNATURES AND COUNTING THEM')
                counter = new Sigcounter(null, ims)
                nsigs = counter.count()
                ims = ims.slice((counter.qb64()).length, ims.length)
            } catch (error) {
                console.log("Cought  ERROR WHILE EXTRACTING SIGNATURES ##",ims)
                nsigs = 0
            }

            // let sigers = []

            if (nsigs) {
                for (let i in range(nsigs)) {
                    //  # check here for type of attached signatures qb64 or qb2
                    let  args = [null,null,null,derivationCodes.SigTwoCodex.Ed25519,0,ims]
                   var siger = new Siger(null,...args)
                   siger.set_verfer(siger.verfer())
                    sigers.push(siger)
                    
                    ims =  ims.slice(0, (siger.qb64()).length)
                   // STRIPPING OF SIGNATURES
                }
            }
            else {  //  iF THERE IS no info on attached sigs
                if (framed) {   //parse for signatures until end-of-stream
                    console.log("\nchecking signatures in the whole frame :")
                    while (ims) {
                        let  args = [null,null,null,derivationCodes.SigTwoCodex.Ed25519,0,ims]
                        siger = new Siger(null,...args)
                        sigers.push(siger)
                        ims =  ims.slice(0, (siger.qb64()).length)
                    }
                }
            }

            if (!sigers) {
                throw `Missing attached signature(s).`
            }
            console.log("\nSIGNATURES FOUND : ")
            console.log("\nPROCESSING (DESERIALIZED MESSAGE + SIGNATURE) EVENTS AFTER COLLECTING SIGNATURES:")

          this.processEvent(serder, sigers)
            console.log("################## VALUE OF ILKS is ###########",serder.ked()['ilk'])
        } else if (ilk == Ilks.rct) {


            try {
                let counter = new CryCounter(null,ims)  //# qb64
                let ncpts = counter.count()
                delete ims.slice(0, (counter.qb64()).length)
            } catch (error) {
                ncpts = 0
            }

            if (ncpts) {
                for (let i in range(ncpts)) {
                    let verfer = new Verfer(null,ims)
                    delete ims.slice(0, (verfer.qb64()).length)
                    let sigver = new Sigver(null,derivation_code.twoCharCode.Ed25519,verfer,0,)
                    sigvers.push(sigver)
                    delete ims.slice(0, (verfer.qb64()).length)
                }
            } else {
                if (framed) {
                    while (ims) {
                        verfer = new Verfer(qb64b = ims)
                        delete ims.slice(0, (verfer.qb64()).length)

                        let sigver = new Sigver(qb64b = ims, verfer = verfer)
                        sigvers.push(sigver)

                        delete ims.slice(0, (sigver.qb64()).length)
                    }
                }
            }

            if (!sigvers)
                throw `Missing attached receipt couplet(s).`

            this.processReceipt(serder, sigvers)


        } else if (ilk == Ilks.vrc) {
            console.log("INSIDE Ilks.vrc",ims)
            let nsigs = null
            try {
                // raw=null, qb64b=null, qb64=null, qb2=null, code=codeAndLength.CryCntCodex.Base64,index=null, count=null
               counter = new Sigcounter(null, ims,null,null,derivationCodes.SigCntCodex.Base64)  //# qb64
            //    console.log("INSIDE TRY CATCH ==============>",a)
                nsigs = counter.count()
                
                ims = ims.slice((counter.qb64()).length, ims.length)
            } catch (error) {
                console.log("Error :",error)
                nsigs = 0
            }
                // console.log("nsigs =========================>",a.count())
            if (nsigs) {
                console.log("NSIGS :",ims.toString())
                for (let i in range(nsigs)) {
                    let  args = [null,null,null,derivationCodes.SigTwoCodex.Ed25519,0,ims]
                    let siger = new Siger(null,...args)
                    
                    siger.set_verfer(siger.verfer())
                    sigers.push(siger)
                    ims = ims.slice(0, (siger.qb64()).length)
                }
            }   else {
                // console.log(" ######################INSIDE ELSE BLOCK ======================>")
                if (framed) {
                    while (ims) {
                        let  args = [null,null,null,derivationCodes.SigTwoCodex.Ed25519,0,ims]
                       let siger = new Siger(null,...args)
                        sigers.push(siger)

                        ims = ims.slice(0, (siger.qb64()).length)
                    }
                }
            }

            if (!sigers) {
                throw `Missing attached signature(s) to receipt.`
            }

            this.processChit(serder, sigers)
        } else {
            throw `Unexpected message ilk = ${ilk}.`
        }
    }


    /**
     * @description Process one event serder with attached indexd signatures sigers
     * Receipt dict labels
            vs  # version string
            pre  # qb64 prefix
            ilk  # rct
            dig  # qb64 digest of receipted event
     */
    processEvent(serder, sigers) {
      console.log("\nINSIDE PROCESS EVENT : ")
        let prefixer, dig, kever, dgkey_, sno = null
        let signers = []
        let signers_icp = []
        let ked = serder.ked()
    
        serder.set_ked(ked)
        var date = new Date()

        try {
            console.log("\n\nked PRE IS :>  ",ked["pre"])
            console.log("\n CHECKING IF PRE IN EVENT IS VALID OR NOT \n")
            prefixer = new Prefixer(null, derivationCodes.oneCharCode.Ed25519N, null, null, null, ked["pre"])
        } catch (error) {
            throw `Invalid pre = ${ked["pre"]}.`

        }
console.log("BASE64 VERSION OF PREFIXER: ======================>",prefixer.qb64())
console.log("\nCOLLECTING DATA LKE : BASE64 PRE,SERIAL NO,MESSAGE DIGEST")
        let pre = prefixer.qb64()
        let ilk = ked["ilk"]

        let sn = ked['sn']
        if (sn.length > 32) {
            throw `Invalid sn = ${sn} too large.`
        }

        try {
            sn = parseInt(sn, 16)
        } catch (error) {
            throw `Invalid sn = ${sn}`
        }

        dig = serder.dig()


        if ((!(this.kevers[pre] === pre))) {
            if (ilk == Ilks.icp) {
                console.log('CALLING KEVER TO VERIFY INCEPTION EVENT ,SIGNATURES  AND PUSH IT TO DB')
                // # kever init verifies basic inception stuff and signatures
                // # raises exception if problem adds to KEL Kevers
                // # create kever from serder
                kever =   new Kever(serder,sigers, null,this.logger)
                
                this.kevers[pre] = kever
                // console.log("this.kevers :", this.kevers)
            } else {
                console.log("INSIDE  ELSE PART line 305")
                dgkey_ = dgkey(pre, dig)
                    this.logger.putDts(dgkey_, Buffer.from(date.toISOString(),'binary'))
                for(let siger in sigers){
                    signers[siger] =   sigers[siger].qb64b()
                }
                console.log("ADDING SIGNATURES======>")
                  this.logger.putSigs(dgkey_,signers)
                console.log("ADDING putEvt======>")
                   this.logger.putEvt(dgkey_, serder.raw())
                console.log("ADDING addOoe======>")
                  this.logger.addOoe(snkey(pre, sn), dig)
            }
        } else {
            console.log("INSIDE  ELSE PART line 316")
            if (ilk == Ilks.icp) {
                console.log("INSIDE  if PART line 318")
                dgkey_ = dgkey(pre, dig)
                this.logger.putDts(dgkey_, Buffer.from(date.toISOString(),'binary'))
                for(let siger in sigers){
                    signers_icp[siger] =   sigers[siger].qb64b()
                }
                // console.log("Pushing SIGNATURES AND EVENTS --------->")
                 this.logger.putSigs(dgkey_, signers_icp)
                this.logger.putEvt(dgkey_, serder.raw())
                this.logger.addLde(snkey(pre, sn), dig)
            } else {
console.log("INSIDE  ELSE PART line 329")
                kever = this.kevers[pre] // # get existing kever for pre
                sno = kever.sn + 1  //# proper sn of new inorder event
                if (sn > sno)           //  # sn later than sno so out of order escrow
                {
                    dgkey_ = dgkey(pre, dig)
                    this.logger.putDts(dgkey_, Buffer.from(date.toISOString(),'binary'))

                    for(let siger in sigers){
                        signers[siger] =   sigers[siger].qb64b()
                    }
                    this.logger.putSigs(dgkey_, signers)
                    this.logger.putEvt(dgkey_, serder.raw())
                    this.logger.addOoe(snkey(pre, sn), dig)
                } else if ((sn == sno) ||
                    (ilk == Ilks.rot && kever.lastEst.sn < sn <= sno)) {
                        console.log("\nUPDATING KEVER :")
                    kever.update(serder = serder, sigers = sigers)

                } else {
                    console.log("INSIDE  ELSE PART line 349")
                    dgkey_= dgkey(pre, dig)
                    this.logger.putDts(dgkey_, Buffer.from(date.toISOString(),'binary'))

                    for(let siger in sigers){
                        signers[siger] =   sigers[siger].qb64b()
                    }
                    this.logger.putSigs(dgkey_,signers)
                    this.logger.putEvt(dgkey_, serder.raw())
                    this.logger.addLde(snkey(pre, sn), dig)
                }




            }


        }

    }



    /**
     * @description  Process one receipt serder with attached sigvers
     * @param {*} serder 
     * @param {*} sigvers 
     */
async    processReceipt(serder, sigvers){

       let ked = serder.ked()
       let pre = ked["pre"]
       let  sn = ked["sn"]
            let dig,snkey,ldig,eserder,couplet = null
       if(sn.length > 32){
        throw `Invalid sn = ${sn} too large.`
       }
       try{
        sn = parseInt(sn,16)
    }catch(error){
        throw `Invalid sn = ${sn}`
    }

    dig = ked["dig"]
   // # Only accept receipt if for last seen version of event at sn
    snkey = await snkey(pre, sn)
    ldig = await this.logger.getKeLast(snkey)   // retrieve dig of last event at sn.


  //  # retrieve event by dig
  let  dgkey_ =  dgKey(pre, dig)
    raw =  self.logger.getEvt(dgkey_)    //# retrieve receipted event at dig

    if(ldig){

        ldig = ldig.toString('utf-8')
        if(ldig != dig){
            throw `Stale receipt at sn = ${ked["sn"]}`
        }

        eserder =  new Serder(Buffer.from(raw,'binary')) 

        for(sigver in sigvers){
            if(!sigver.verfer.nontrans){
                {}
            }
            if(sigver.verfer.verify(sigver.raw(), eserder.raw())){

                couplet = sigver.verfer.qb64b() + sigver.qb64b()
                    this.logger.addRct(dgkey, couplet)
            }

        }
    }else {
        if(raw){

            throw `Bad receipt for sn = ${ked["sn"]} and dig = ${dig }.`
        }

        for(sigver in sigvers){
            if(!sigver.verfer.nontrans){
                {}
            }
            if(sigver.verfer.verify(sigver.raw(), eserder.raw())){

                couplet = sigver.verfer.qb64b() + sigver.qb64b()
                    this.logger.addUre(dgkey, couplet)
            }

        }
    }
    }



/**
 * @description  Process one transferable validator receipt (chit) serder with attached sigers
 * @param {} serder serder is chit serder (transferable validator receipt message)
 * @param {*} sigers    sigers is list of Siger instances that contain signature

 */
    processChit(serder, sigers){

            let dig,seal,sealet,snKey_,dgKey_,ldig,raw,rekever,triplet = null
       let ked = serder.ked()
       serder.set_ked(ked)
       
        serder.set_raw(serder.raw())
       let pre = ked["pre"]
       let  sn = ked["sn"]

       if(sn.length > 32){
           throw `Invalid sn = ${sn} too large.`
       }

       try{
           sn = parseInt(sn,16)
       }catch(error){
           throw `Invalid sn = ${sn}`
       }
       console.log("ked ============>",ked)
       dig = ked["dig"]
        SealEvent.pre = ked["seal"].pre
        SealEvent.dig = ked["seal"].dig
        // seal = SealEvent
        console.log("seal ==============>" , '\n\n\n',SealEvent)
       sealet = [Buffer.from(SealEvent.pre,'binary'), Buffer.from(SealEvent.dig,'binary')]
       sealet = Buffer.concat(sealet)

       snKey_ = snkey(pre,sn)
       console.log("snKey =====>",snKey_.toString())
       ldig = this.logger.getKeLast(snKey_)  // # retrieve dig of last event at sn.

       dgKey_ = dgkey(pre,dig)
       raw = this.logger.getEvt(dgKey_) // # retrieve receipted event at dig
    //    ldig = 'EmYgkUTsZkHtqGS-hd99wy_WYQJHHx9g0YqYV--j5je0'
       ldig =  this.logger.getKes(snKey_)
       for(let i = 0 ; i < ldig.length ;i++){
           console.log(ldig[i].toString())
       }
      
       if(ldig){
        //    ldig = ldig.toString()  
           console.log("LDIG and DIG are =================>",ldig.toString(),dig)    
           if(ldig[0].toString() != dig){
               throw `Stale receipt at sn = ${ked["sn"]}`
           }     
       }else {
        if(raw){
            throw `Bad receipt for sn = ${ked["sn"]} and dig = ${dig}.`
        }

       }


    //    # assumes db ensures that:
    //    # if ldig is not None then raw is not None and vice versa
    //    # if ldig == dig then eraw must not be none

    if (ldig !=null && raw !=null && SealEvent.pre in this.kevers){

        rekever = this.kevers[SealEvent.pre]

        if (rekever.lastEst.dig != SealEvent.dig)
        throw `Stale receipt for pre = ${pre} dig = ${dig} from validator = ${seal.pre}.`
        console.log("raw ========================>",raw.toString())
        // raw = Buffer.from(raw,'binary')
       
        for (let siger in sigers ){
            if(sigers[siger].index() >=(rekever.verfers).length){
                throw `Index = ${sigers[siger].index} to large for keys.`
            }
            sigers[siger].set_verfer(rekever.verfers[sigers[siger].index()] )
            // sigers[siger].verfer = rekever.verfers[sigers[siger].index()] 
            // console.log("sigers[siger] =====================>",raw,'\n\n',(sigers[siger].raw()))
            if(sigers[siger].verfer().verify(sigers[siger].raw(), raw)){
                triplet = sealet + sigers[siger].qb64b()
                // console.log("triplet ======================+>",triplet)
                    this.logger.addVrc(dgKey_,triplet)
            }
        }
    }else {
        for (let siger in sigers ){
            triplet = sealet + sigers[siger].qb64b()
            this.logger.addVre(dgKey_, triplet)
        }
    }

    }




    /**
     * @description  Processes potential duplicitous events in PDELs

        Handles duplicity detection and logging if duplicitous

        Placeholder here for logic need to move
     * @param {*} serder 
     * @param {*} sigers 
     */
    duplicity(serder, sigers){

        let [prefixer,pre,ked,ilk,sn,dig] = null
        let ked = serder.ked

        try{
            prefixer = new Prefixer(null,null,null,null,null,qb64=ked["pre"])
        }catch(err){
throw `Invalid pre = ${ked["pre"]}.`
        }

        pre = prefixer.qb64
        ked = serder.ked
        ilk = ked["ilk"]

        try{
            sn = parseInt(ked["sn"], 16)
        }catch(err){
            throw `Invalid sn = ${ked["sn"]}`
        }
        dig = serder.dig



        if (ilk == Ilks.icp){
            kever = new Kever(serder=serder, sigers=siger, logger=self.logger)
        }else {
            {}
        }

    }
}

module.exports = {Kevery}