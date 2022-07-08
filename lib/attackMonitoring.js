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
var violations = 0;
//default violationLimit is 100.
var violationLimit = 100;
var violationTime = 0;
var nssVersion = "";

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

function checkOutboundRequest(outBoundReqDomain, reportUri, stack, blockedArray, allowedArray, allowedModuleArray){
    //blockedWildcardDomains => array of domains where all sub domains are blocked. (*)
    const blockedWildcardDomains = blockedArray.filter(domain => domain[0] == "*");
    //blockedDomains => array of domains to be blocked. (without wildcard)
    const blockedDomains = blockedArray.filter(domain => domain[0] !== "*");
    //allowedWildcardDomains => array of domains where sub domains are allowd. (*)
    const allowedWildcardDomains = allowedArray.filter(domain => domain[0] == "*");
    //allowedDomains => array of domains which are allowed. (without wildcard)
    const allowedDomains = allowedArray.filter(domain => domain[0] !== "*");

    /**
     * Allow outbound requests to reportUri
     */
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
     * Check if Call Back Function is already defined.
     * If not defined, assign it.
     * If defined, cant reassign until server is restarted.
     */
    if (!iscbFunctionDefined) {
        cbFunction = callbackFunction;
    }

    /**
     * If attackMonitoring not enabled.
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
            const reportUri = new URL(policyJSON.reportUri);

            // Set the violationLimit
            if (policy.hasOwnProperty('maxViolationsPerMinute')){
                violationLimit = policy['maxViolationsPerMinute'];
            }

            // Reset the violationTime and violations every minute.
            setInterval(violationReset, 60000);

            if ((blockedArray.length + allowedArray.length) > 0) {

                //Enable attackMonitoring
                attackMonitoring = true;
                console.log('NSS : Attack Monitoring enabled. ');

                //Get NodeSecurityShield Version
                nssVersion = require('../package.json').version;

                allowOutboundRequest = (outBoundReqDomain, stack) => {
                    // Check outBoundReqDomain.
                    return checkOutboundRequest(outBoundReqDomain, reportUri, stack, blockedArray, allowedArray, allowedModuleArray);
                }

            }

        }

    }

}

// Send CSP Report.
function sendReport(reportUri, violationEvent){
    const data = JSON.stringify(violationEvent);
    const url = new URL(reportUri);
    const options = {
        host: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
            'Content-Type': 'application/csp-report',
            'Content-Length': data.length,
            'User-Agent': "Node Security Shield/" + nssVersion,
        },
    };
    // Check if reportUri is http or https.
    const req = (url.protocol == 'https:' ? https : http).request(options, res => {
        //console.log(`Sent violation report with status code : ${res.statusCode}`);
    });
    req.write(data);
    req.end();
}

// Reset violations and log if reports were not sent for some violations.
function violationReset(){
    if (violations > violationLimit) {
        console.log(violations - violationLimit + " more violations occured but details not captured.");
    }
    violationTime = 0;
    violations = 0;
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
                violations++;
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

                // For first violation in this minute.
                if (violations === 1) {
                    violationTime = new Date().getTime();
                }
                // If limit has not been reached, send csp report.
                if (violationLimit - violations >= 0) {
                    sendReport(policy['reportUri'], violationEvent);
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
