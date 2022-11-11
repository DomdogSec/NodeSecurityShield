const http = require('http');
const https = require('https');

// Make local copy of JSON.stringify and setTimeout
const stringify = JSON.stringify;
const timeoutSet = setTimeout;

//default state is false.
let allowOutboundRequest = false;
let allowCommand = false;
let policy;
let cbFunction;
let app;
let attackMonitoring = false; // Default, not enabled.
var violations = 0;
//default violationLimitPerMin is 100.
var violationLimitPerMin = 100;
//default is false, is true when violations > violationLimitPerMin
var violationLimitPerMinReached = false;
var nssVersion;
var reportUri;
var reportUriDomain;
var reportUriIsHttp = false;

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

function extractHostname(url) {
  var hostname;
  //find & remove protocol (http, ftp, etc.) and get hostname

  if (url.indexOf("//") > -1) {
    hostname = url.split('/')[2];
  } else {
    hostname = url.split('/')[0];
  }

  //find & remove port number
  hostname = hostname.split(':')[0];
  //find & remove "?"
  hostname = hostname.split('?')[0];

  return hostname.toLowerCase();
}

function checkOutboundRequest(outBoundReqDomain, stack, blockedArray, allowedArray, allowedModuleArray){
    //blockedWildcardDomains => array of domains where all sub domains are blocked. (*)
    const blockedWildcardDomains = blockedArray.filter(domain => domain[0]+domain[1] == "*.");
    //blockedDomains => array of domains to be blocked. (without wildcard)
    const blockedDomains = blockedArray.filter(domain => domain[0] !== "*");
    //allowedWildcardDomains => array of domains where sub domains are allowd. (*)
    const allowedWildcardDomains = allowedArray.filter(domain => domain[0]+domain[1] == "*.");
    //allowedDomains => array of domains which are allowed. (without wildcard)
    const allowedDomains = allowedArray.filter(domain => domain[0] !== "*");

    outBoundReqDomain = outBoundReqDomain.toLowerCase();

    /**
     * Allow outbound requests to reportUri
     */
    if (outBoundReqDomain === reportUriDomain) {
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

    if (allowedArray.length + allowedModuleArray.length === 0) {
        return true
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
            let allowedModuleWildcardDomains = allowedModuleArray[i].domains.filter(domain => domain[0]+domain[1] == "*.");
            let modulePaths = allowedModuleArray[i].modules.map(module => module.file);
            if (allowedModuleDomains.includes(outBoundReqDomain)){
                for (j=0; j < modulePaths.length; j++){
                    const regex = new RegExp(modulePaths[j]);
                    if(regex.test(fileLines)){
                        //Outbound Request allowed
                        return true;
                    }
                }
            }else {
                for (j = 0; j < allowedModuleWildcardDomains.length; j++) {
                    if (wildcardCheck(allowedModuleWildcardDomains[j], outBoundReqDomain)){
                        for (k=0; k < modulePaths.length; k++) {
                            const regex = new RegExp(modulePaths[k]);
                            if(regex.test(fileLines)){
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

function checkExecutedCommand(command, allowedCommands) {
    for (i = 0; i < allowedCommands.length; i++) {
        const regex = new RegExp(allowedCommands[i]);
        if(regex.test(command)) {
            return true;
        }
    }
    return false;
}

/**
 * callbackFunction for handling RAP violations
 *
 * @callback callbackFunction
 * @param {JSON} violationEvent RAP violation which occurred. It is presented as a CSP violation.
 * @param {Number} violations  RAP violation count. Resets to ZERO every minute.
 * @param {Boolean} violationLimitPerMinReached true if RAP violations count exceeds 'maxViolationsPerMinute'
 *
 */

/**
 * For outBoundRequest  , blockedDomains have greater presidence over allowedDomains.
 * i.e., requests are checked against blockedDomains first then allowedDoamins.
 *
 * @param {String} appId A unique identifier for this instance of NSS
 * @param {Object} policyJSON Resource Access Policy as a JSON
 * @param {callbackFunction} callbackFunction - callbackFunction that handles RAP violations
 */
let enableAttackMonitoring = function (appId, policyJSON, callbackFunction) {
    /**
     * Set appId. Changing it requires a server/application restart.
     */
    if (typeof app === 'undefined') {
        app = appId;
    }

    /**
     * Set Resource Access Policy. Changing it requires a server/application restart.
     */
    if (typeof policy === 'undefined') {
        policy = policyJSON;
    }

    /**
     * Set callbackFunction. Changing it requires a server/application restart.
     */
    if (typeof cbFunction === 'undefined') {
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

         // check and set reportUri
         if (policyJSON.hasOwnProperty('reportUri')){
             if (isString(policyJSON.reportUri)){
                 reportUri = policyJSON.reportUri;
                 reportUriDomain = extractHostname(reportUri);
                 if (reportUri.toLowerCase().startsWith("http:")) { // its http
                     reportUriIsHttp = true;
                 }

                 // check and set the violationLimitPerMin
                 if (policyJSON.hasOwnProperty('maxViolationsPerMinute')){
                     if (typeof policyJSON['maxViolationsPerMinute'] === 'number') {
                         violationLimitPerMin = policyJSON['maxViolationsPerMinute'];
                     }else{
                        // todo: log - RAP's  maxViolationsPerMinute value is expected to be a number
                     }
                 }

                 // Reset the violations count every minute.
                 setInterval(violationReset, 60000);
             }else{
                 // todo: log - RAP's reportUri value is expected to be a string
             }
         }

        // Check if any valid property for attackMonitoring is present in policyJSON.
        if (policyJSON.hasOwnProperty('outBoundRequest') || policyJSON.hasOwnProperty('executedCommand')) {

            var totalLength = 0;
            if ("outBoundRequest" in policyJSON) {
                //todo: enable logging for policy file related exceptions
                const blockedArray = policyJSON.outBoundRequest.blockedDomains.map(e => e.trim()).map(e => e.toLowerCase());
                const allowedArray = policyJSON.outBoundRequest.allowedDomains.filter(domain => isString(domain)).map(e => e.trim()).map(e => e.toLowerCase());
                const allowedModuleArray = policyJSON.outBoundRequest.allowedDomains.filter(domain => isPureObject(domain)).map(function(obj){
                obj.domains = obj.domains.map(e => e.toLowerCase());
                return obj;});

                if ((blockedArray.length + allowedArray.length + allowedModuleArray.length) > 0) {
                    totalLength += blockedArray.length + allowedArray.length + allowedModuleArray.length;
                    allowOutboundRequest = (outBoundReqDomain, stack) => {
                        // Check outBoundReqDomain.
                        return checkOutboundRequest(outBoundReqDomain, stack, blockedArray, allowedArray, allowedModuleArray);
                    }

                }

            }

            if ("executedCommand" in policyJSON) {
                const allowedCommandsArray = policyJSON.executedCommand.allowedCommands.map(e => e.trim()).map(e => e.toLowerCase());

                if (allowedCommandsArray.length > 0) {
                    totalLength += allowedCommandsArray.length;
                    allowCommand = (executedCommand) => {
                        // Check executedCommand.
                        return checkExecutedCommand(executedCommand, allowedCommandsArray);
                    }
                }
            }

            // attackMonitoring is enabled only if there are any valid entries
            if (totalLength > 0) {
                //Enable attackMonitoring
                attackMonitoring = true;
                console.log('NSS : Attack Monitoring enabled. ');

                //Get NodeSecurityShield Version
                nssVersion = require('../package.json').version;
            }

        }




    }

}

// Send CSP Report.
function sendReport(violationEvent){
    const url = reportUri;
    const data = stringify(violationEvent);
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/csp-report',
            'Content-Length': data.length,
            'User-Agent': "Node Security Shield/" + nssVersion,
        },
    };
    // Check if reportUri is http or https.
    if (reportUriIsHttp) {
        const req = http.request(url, options);
        req.write(data);
        req.end();
    } else {
        const req = https.request(url, options);
        req.write(data);
        req.end();
    }
}

// Reset violations
function violationReset() {
    violations = 0;
}

// Prepare CSP Report according to eventType.
function prepareReport(args, eventType, stack) {
    let cspReport = {};
    let blockedParam;
    let directive;
    let scriptSample = "";
    switch (eventType) {
        case 'socket':
            directive = "connect-src";
            blockedParam = args.protocol + "//" + args.host + ":" + args.port;
            break;
        case 'command':
            directive = "script-src";
            blockedParam = "https://command-execution";
            scriptSample = args.join(' ');
            break;
    }
    cspReport["document-uri"] = "https://"+app;
    cspReport["blocked-uri"] = blockedParam;
    cspReport["violated-directive"] = directive;
    cspReport["effective-directive"] = directive;
    cspReport["original-policy"] = stringify(policy);
    cspReport["disposition"] = "report";
    cspReport["status-code"] = 200;
    cspReport["script-sample"] = scriptSample;
    cspReport["source-file"] = stack;
    return cspReport;
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
                violationEvent["csp-report"] = prepareReport(arg0, "socket", stack);

                // If reportUri has been set and limit has not been reached, send csp report.
                if ( typeof reportUri === 'string') {
                    if (violationLimitPerMin - violations >= 0) {
                        timeoutSet(sendReport, 10, violationEvent);
                    }
                }

                cbFunction(violationEvent, violations, violationLimitPerMinReached);
            }
        } else {
            //todo: log if there is no port or  no host in arguments.
            //console.log(args)
            //console.log("Host and Port are not part of the argument passed to net.socket.connect")
        }
    }
}

let checkCommandExecution = function(args, stack) {
    let arg0;
    arg0 = args['0'].args;
    var executedCommand = args['0'].args.join(' ');
    if (!allowCommand(executedCommand)) {
        violations++;
        let violationEvent = {};
        violationEvent["csp-report"] = prepareReport(arg0, 'command', stack);
        if (typeof reportUri === 'string') {
            if (violationLimitPerMin - violations >= 0) {
                timeoutSet(sendReport, 10, violationEvent);
            }
        }
        cbFunction(violationEvent, violations, violationLimitPerMinReached);
    }
}

let resourceAccessPolicyCheck = function (eventType, args, stack) {
    //Check if attackMonitoring is enabled.
    if (attackMonitoring) {
        switch (eventType) {
            case 'socket':
                checkSocketConnection(args, stack);
                break;
            case 'command':
                checkCommandExecution(args, stack);
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
