const https = require('https');
const http = require('http');

//default state is false.
let allowOutboundRequest = false;
let policy;
let cbFunction;
let attackMonitoring = false; // Default, not enabled.
let iscbFunctionDefined = false; //Default, not defined. When true, can change cbFUnction at runtime.
let cbFuncitonLine = "at TLSSocket.obj.<computed> [as connect] (/mnt/c/Ironwasp/Product/NodeSecurityShield/lib/hook.js:22:13)"
//Error.stackTraceLimit = 60
var reportUriHosts = [];

function isPureObject(input) {
  return null !== input && typeof input === 'object' && Object.getPrototypeOf(input).isPrototypeOf(Object);
}

function isString(input) {
    return typeof input === 'string';
}

function wildcardCheck(wildcardDomain, outBoundReqDomain) {
    wildcardDomain = wildcardDomain.split('*').pop();
    if (outBoundReqDomain.length > wildcardDomain.length) {
        if (outBoundReqDomain.substr(outBoundReqDomain.length - wildcardDomain.length) == wildcardDomain) {
            return true;
        }
    }
    return false;
}
/**
 * For outBoundRequest  , blockedDomains have greater presidence over allowedDomains.
 * i.e., requests are checked against blockedDomains first then allowedDoamins.
 *
 * @param {Object} policyJSON
 * @param {function} callbackFunction
 */
let enableAttackMonitoring = function (policyJSON, callbackFunction) {
    policy = policyJSON;
    /**
     * Check if Call Back Funciton is already defined.
     * If not defined assign it.
     * If defiend, cant reassign untill server is restarted.
     */
    if (!iscbFunctionDefined) {
        cbFunction = callbackFunction;
    }

    /**
     * If attackMonitoring not enbaled.
     */
    if (!attackMonitoring) {

        /**
         * Check for 'outBoundRequest' in RAP.
         * If exists and contains entries,
         * then enable Attack Monitoring for all outbound requests.
         */
        if ("outBoundRequest" in policyJSON) {
            //todo: enable logging for policy file related exceptions
            const blockedArray = policyJSON.outBoundRequest.blockedDomains.map(e => e.trim());
            const allowedArray = policyJSON.outBoundRequest.allowedDomains.filter(domain => isString(domain)).map(e => e.trim());
            const allowedModuleArray = policyJSON.outBoundRequest.allowedDomains.filter(domain => isPureObject(domain));

            if ((blockedArray.length + allowedArray.length) > 0) {

                //Enable attckMonitoring
                attackMonitoring = true;
                console.log('NSS : Attack Monitoring enabled. ');
                //blockedWildcardDomains => array of domains where all sub domains are blocked. (*)
                const blockedWildcardDomains = blockedArray.filter(domain => domain[0] == "*");
                //blockedDomains => array of domains to be blocked. (without wildcard)
                const blockedDomains = blockedArray.filter(domain => domain[0] !== "*");
                //allowedWildcardDomains => array of domains where sub domains are allowd. (*)
                const allowedWildcardDomains = allowedArray.filter(domain => domain[0] == "*");
                //allowedDomains => array of domains which are allowed. (without wildcard)
                const allowedDomains = allowedArray.filter(domain => domain[0] !== "*");

                allowOutboundRequest = (outBoundReqDomain, stack) => {

                    /**
                     * Allow outbound requests to reportUri
                     */
                    const reportUri = new URL(policy.reportUri)
                    if (outBoundReqDomain === reportUri.hostname) {
                        return true
                    }

                    if (blockedArray.length > 0) {
                        //check outbound request in blockedDomains (without wildcard)
                        if (blockedDomains.includes(outBoundReqDomain)) {
                            //Outbound Request not allowed

                            return false;
                        } else {//check outbound request in blockedWildcardDomains
                            for (i = 0; i < blockedWildcardDomains.length; i++) {
                                if (wildcardCheck(blockedWildcardDomains[i], outBoundReqDomain)){
                                    //Outbound Request not allowed
                                    return false;
                                }
                            }
                        }
                    }
                    if (allowedArray.length > 0) {
                        //check outbound request in allowedDomains (without wildcard)

                        if (allowedDomains.includes(outBoundReqDomain)) {
                            //Outbound Request allowed
                            return true;
                        } else { // check outbound request in allowedWildcardDomains
                            for (i = 0; i < allowedWildcardDomains.length; i++) {
                                if(wildcardCheck(allowedWildcardDomains[i], outBoundReqDomain)){
                                    //Outbound Request allowed
                                    return true;
                                }
                            }
                        }
                    }

                    if (allowedModuleArray.length > 0) {
                        //check outbound request and module in allowedModuleArray
                        let fileLines;
                        const lines = stack.split('\n').slice(1);
                        fileLines = lines.map(function(line){
                            const lineMatch = line.match(/at (?:(.+?)\s+\()?(?:(.+?):(\d+)(?::(\d+))?|([^)]+))\)?/);
                            const fileName  = lineMatch[2];
                            return fileName;
                        }).join('\n');
                        for (i = 0; i < allowedModuleArray.length; i++) {
                            let allowedModuleDomains = allowedModuleArray[i].domains.filter(domain => domain[0] != "*");
                            let allowedModuleWildcardDomains = allowedModuleArray[i].domains.filter(domain => domain[0] == "*");
                            let modulePaths = allowedModuleArray[i].modules.map(module => module.file);
                            if (allowedModuleDomains.includes(outBoundReqDomain)){
                                for (j=0; j < modulePaths.length; j++){
                                    const regex = new RegExp(modulePaths[j]);
                                    if(regex.test(stack)){
                                        //Outbound Request allowed
                                        return true;
                                    }
                                }
                            }else {
                                for (j = 0; j < allowedModuleWildcardDomains.length; j++) {
                                    if (wildcardCheck(allowedModuleWildcardDomains[j], outBoundReqDomain)){
                                        for (k=0; k < modulePaths.length; k++) {
                                            const regex = new RegExp(modulePaths[k]);
                                            if(regex.test(stack)){
                                                //Outbound Request allowed
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    //default state is to false.
                    return false;
                }

            }

        }
    }


}

let checkSocketConnection = function (args, stack) {

    let arg0;
    if (Array.isArray(args[0])) { //true if HTTP
        arg0 = args[0][0];
    } else {
        arg0 = args[0];
    }
    if (typeof arg0 === 'object' && arg0 !== null) {
        if (('port' in arg0) && ('host' in arg0)) { // TCP Connection.
            if (!allowOutboundRequest(arg0.host, stack)) {
                let violationEvent = {};
                let cspReport = {};
                cspReport["document-uri"] = "file://" + module.parent.parent.parent.filename;
                cspReport["blocked-uri"] = arg0.protocol + "//" + arg0.host + ":" + arg0.port;
                cspReport["violated-directive"] = "connect-src";
                cspReport["effective-directive"] = "connect-src";
                cspReport["original-policy"] = JSON.stringify(policy);
                cspReport["disposition"] = "report";
                cspReport["status-code"] = 200;
                cspReport["script-sample"] = "";
                cspReport["source-file"] = stack;
                violationEvent["csp-report"] = cspReport;
                cbFunction(violationEvent);
                if (policy.hasOwnProperty('reportUri')) {
                    const data = JSON.stringify(violationEvent);
                    const url = new URL(policy["reportUri"]);
                    const options = {
                        host: url.hostname,
                        port: url.port,
                        path: url.pathname + url.search,
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/csp-report',
                            'Content-Length': data.length,
                            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0',
                        },
                    };
                    const req = (url.protocol == 'https:' ? https : http).request(options, res => {
                        //console.log(`Sent violation report with status code : ${res.statusCode}`);
                    });
                    req.write(data);
                    req.end();
                }
            }
        } else {
            //todo: log if there is no port or  no host in arguments.
            //console.log(args)
            //console.log("Host and Port are not part of the argument passed to net.socket.connect")
        }
    }
}

let resourceAccessPolicyCheck = function (eventType, args, stack) {
    //Check if attackMonitoring is enabled.
    if (attackMonitoring) {
        switch (eventType) {
            case 'socket':
                checkSocketConnection(args, stack);
                break;
        }
    } else {
        //todo: provide detailed INFO logs.
        //console.log('Attack Monitoring not enabled. ');
        //console.log('To enable : nodeSecurityShield.enableAttackMonitoring(resourceAccessPolicy ,callbackFunction)');
    }
}


module.exports = {
    enableAttackMonitoring: enableAttackMonitoring,
    resourceAccessPolicyCheck: resourceAccessPolicyCheck
}
