/* ***** BEGIN LICENSE BLOCK *****
Copyright (C) 2013-2015 CZ.NIC z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator Add-on.

DNSSEC/TLSA Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC/TLSA Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */


//---------------------------------------------------------
// Init and unload of add-on and its plugin core
//---------------------------------------------------------
window.addEventListener("load", function() {cz.nic.extension.dnssecValidator.init();}, false);
window.addEventListener("unload", function() {cz.nic.extension.dnssecValidator.uninit();}, false);


//---------------------------------------------------------
// Create worker for async call of dnssec validation core
//---------------------------------------------------------
cz.nic.extension.dnssecworker =
    new ChromeWorker("chrome://dnssec/content/dnsseclib.js");


/* ========================================================================= */
/*
 * Callback from dnssecworker (dnsseclib.js), return validation status
 */
cz.nic.extension.dnssecworker.onmessage = function(event) {
/* ========================================================================= */
	var retval = event.data.split("§");

	switch (retval[0]) {
	case "initialiseRet":
		if ("tryAgain" == retval[1]) {
			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.debugPrefix
				    + "Trying to reinitialise worker.\n");
			}
			setTimeout(function() {
				let cmd = "initialise§" +
				    cz.nic.extension.dnssecLibCore.coreFileName;
				cz.nic.extension.dnssecworker.postMessage(cmd);
			}, 500);
		} else if ("fail" == retval[1]) {
			/* Core cannot be initialised. */
			cz.nic.extension.dnssecValidator.initFailed = true;
			cz.nic.extension.dnssecExtPrefs.setBool(
			     "resolvingactive", false);
			cz.nic.extension.dnssecExtHandler.setMode(
			    cz.nic.extension.dnssecExtHandler.
				DNSSEC_MODE_ERROR_GENERIC);
		}
		break;
	case "validateRet":
		if (cz.nic.extension.dnssecValidator.debugOutput) {
			dump(cz.nic.extension.dnssecValidator.debugPrefix +
			    '-------- ASYNC RESOLVING DONE --------------\n\n');
		}

		var dn = retval[1];
		var status = retval[2];
		var ip = retval[3];
		var addr = retval[4];
		cz.nic.extension.dnssecExtResolver.setValidatedData(dn,
		    parseInt(status,10), ip, addr);
		break;
	default:
		break;
	}
};


/* ========================================================================= */
/*
 * Object: DNSSEC Validator core evelope,
 *        interaction with tabs and validation core
 */
cz.nic.extension.dnssecValidator = {
/* ========================================================================= */
dnssecExtID: "dnssec@nic.cz",
debugOutput: false,
debugPrefix: "dnssec: ",
debugStartNotice: "------------ DNSSEC resolving start ---------------\n",
debugEndNotice: "------------ DNSSEC resolving end -----------------\n",
asyncResolveRes: false,
timer: null,
oldAsciiHost: null,
coreinit: false,
initFailed: false,

//---------------------------------------------------------
// initalitasation of dnssec Validator
//---------------------------------------------------------
init: function() {

		// Enable debugging information on stdout if desired
		this.getDebugOutputFlag();

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Start of add-on\n');
		}

		// Plugin initialization
		cz.nic.extension.dnssecLibCore.dnssec_init();

		cz.nic.extension.dnssecExtHandler.setMode(
		    cz.nic.extension.dnssecExtHandler.DNSSEC_MODE_INACTION);

		setTimeout(function() {
			let cmd = "initialise§" +
			    cz.nic.extension.dnssecLibCore.coreFileName;
			cz.nic.extension.dnssecworker.postMessage(cmd);
		}, 500);

		// Enable asynchronous resolving if desired
		this.getAsyncResolveFlag();

		// Change popup-window fore/background color if desired
		this.getPopupColors();

		// Register preferences observer
		cz.nic.extension.validatorExtPrefObserver.register();

		// Create the timer
		this.timer = Components.classes["@mozilla.org/timer;1"]
		.createInstance(Components.interfaces.nsITimer);

		// Get DNSSEC Validator extension object
		if (Application.extensions) {   // Firefox < 3.7, sync
			var dnssecExt =
			    Application.extensions.get(this.dnssecExtID);
			this.showHomepage(dnssecExt);
		} else {   // Firefox >= 3.7, async
			Application.getExtensions(function(extensions) {
			    var dnssecExt = extensions.get(
			    cz.nic.extension.dnssecValidator.dnssecExtID);
			    cz.nic.extension.dnssecValidator.
			         showHomepage(dnssecExt);
			});
		}

		// Listen for webpage events
		gBrowser.addProgressListener(
		     cz.nic.extension.validatorExtUrlBarListener);
	},

//---------------------------------------------------------
// show homepage when validator was updated on new version
//---------------------------------------------------------
showHomepage:
	function(dnssecExt) {
		// Get saved extension version
		var dnssecExtOldVersion =
		     cz.nic.extension.dnssecExtPrefs.getChar("version");
		// Display initialisation page if appropriate
		if (dnssecExt.version != dnssecExtOldVersion) {
			// Save new version
			cz.nic.extension.dnssecExtPrefs
			      .setChar("version", dnssecExt.version);
			// Define timer callback
			this.timer.initWithCallback(
			function() {
				if (gBrowser) {
					gBrowser.selectedTab = 
					    gBrowser.addTab(
					    'http://www.dnssec-validator.cz');
				}
			},
			100,
			Components.interfaces.nsITimer.TYPE_ONE_SHOT);
		}
	},

//---------------------------------------------------------
// get debug enable from preferences
//---------------------------------------------------------
getDebugOutputFlag:
	function() {
		this.debugOutput = 
		    cz.nic.extension.dnssecExtPrefs.getBool("dnssecdebug");
	},

//---------------------------------------------------------
// get async resolving from preferences
//---------------------------------------------------------
getAsyncResolveFlag:
	function() {
		this.asyncResolveRes = 
		    cz.nic.extension.dnssecExtPrefs.getBool("asyncresolve");
	},

//---------------------------------------------------------
// Change popup-window fore/background color if desired
//---------------------------------------------------------
getPopupColors:
	function() {
		var dpw = document.getElementById("dnssec-popup-container");
		dpw.style.color =
		    cz.nic.extension.dnssecExtPrefs.getChar("popupfgcolor");
		dpw.style.backgroundColor =
		    cz.nic.extension.dnssecExtPrefs.getChar("popupbgcolor");
	},

//---------------------------------------------------------
// uninitialization of DNSSEC Validator
//---------------------------------------------------------
uninit:
	function() {

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Stop of add-on\n');
		}

		gBrowser.removeProgressListener(
		    cz.nic.extension.validatorExtUrlBarListener);

		// Unregister preferences observer
		cz.nic.extension.validatorExtPrefObserver.unregister();

		// Reset resolving flag
		cz.nic.extension.dnssecExtPrefs.
		    setBool("resolvingactive", false);

		if (!cz.nic.extension.dnssecValidator.initFailed) {
			// Plugin deinitialization
			cz.nic.extension.dnssecLibCore.
			     dnssec_validation_deinit_core();
			cz.nic.extension.dnssecLibCore.dnssec_close();
		}

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Clear Cache...\n');
		}
	},

//---------------------------------------------------------
// Register observe service for http/https request catching
//---------------------------------------------------------
registerObserver:
	function(topic) {
		var observerService =
		     Components.classes["@mozilla.org/observer-service;1"]
		        .getService(Components.interfaces.nsIObserverService);
		observerService.addObserver(this, topic, false);
	},

//---------------------------------------------------------
// Unregister observe service
//---------------------------------------------------------
unregisterObserver:
	function(topic) {
		var observerService =
		    Components.classes["@mozilla.org/observer-service;1"]
		        .getService(Components.interfaces.nsIObserverService);
		observerService.removeObserver(this, topic);
	},

//---------------------------------------------------------
// is fires when url was changed 
//---------------------------------------------------------
processNewURL:
	function(aLocationURI) {

		var scheme = null;
		var asciiHost = null;
		var utf8Host = null;

		if (cz.nic.extension.dnssecValidator.initFailed) {
			cz.nic.extension.dnssecExtHandler.setMode(
			    cz.nic.extension.dnssecExtHandler.
			        DNSSEC_MODE_ERROR_GENERIC);
			return;
		}

		var freecache =
		    cz.nic.extension.dnssecExtPrefs.getBool("dnsseccachefree");
		if (freecache) {
			cz.nic.extension.dnssecLibCore.
			    dnssec_validation_deinit_core();
			cz.nic.extension.dnssecExtPrefs.
			    setBool("dnsseccachefree", false);
		}

		try {
			// Get URI scheme
			scheme = aLocationURI.scheme;
			// Get punycoded hostname			
			asciiHost = aLocationURI.asciiHost;
			// Get UTF-8 encoded hostname
			utf8Host = aLocationURI.host;
		} catch(ex) {}

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Scheme: "' + scheme + '"; ' +
			     'ASCII domain name: "' + asciiHost + '"');
		}

		// Eliminate chrome scheme, Empty string, IPv4, IPv6
		if (scheme == 'chrome' || asciiHost == null ||
		    asciiHost == '' || asciiHost.indexOf("\\") != -1 ||
		    asciiHost.indexOf(":") != -1 || 
		    asciiHost.search(/[A-Za-z]/) == -1) {

			if (this.debugOutput) {
				dump(' ...invalid\n');
			}
			this.oldAsciiHost = null;
			// Set inaction mode (no icon)
			cz.nic.extension.dnssecExtHandler.setMode(
			     cz.nic.extension.dnssecExtHandler.
			          DNSSEC_MODE_INACTION);
			return;
		// Eliminate duplicated queries
		} else if (asciiHost == this.oldAsciiHost) {
			if (this.debugOutput) {
				dump(' ...duplicated\n');
			}
			return;
		}
		if (this.debugOutput) {
			dump(' ...valid\n');
		}
		// Check DNS security
		cz.nic.extension.dnssecExtHandler.checkSecurity(
		      asciiHost, utf8Host);
	}
};


/* ========================================================================= */
/*
 * Object: TLSA Validator core evelope,
 *        interaction with tabs and validation core
 */
cz.nic.extension.dnssecExtResolver = {
/* ========================================================================= */

//---------------------------------------------------------
// Called when request is not cached already
//---------------------------------------------------------
dnssecValidate:
	function(dn, resolvipv4, resolvipv6, aRecord) {

		// Get DNS resolver address(es)
		var nameserver = cz.nic.extension.dnssecExtPrefs.
		    getChar("dnsserveraddr");

		// Create variable to pass options
		var c = cz.nic.extension.dnssecExtNPAPIConst;
		var options = 0;

		if (cz.nic.extension.dnssecValidator.debugOutput) {
			options |= c.DNSSEC_FLAG_DEBUG;
		}
		if (cz.nic.extension.dnssecExtPrefs.getInt("dnsserverchoose") != 3) {
			options |= c.DNSSEC_FLAG_USEFWD;
		}
		if (resolvipv4) {
			options |= c.DNSSEC_FLAG_RESOLVIPV4;
		}
		if (resolvipv6) {
			options |= c.DNSSEC_FLAG_RESOLVIPV6;
		}

		// Check browser's IP address(es)
		var addr = null;
		// Browser's IP addresses are presumed as valid
		var invipaddr = false;
		if (aRecord) {
			aRecord.rewind();
			// Address list has another item
			if (aRecord.hasMore()) { 
				addr = aRecord.getNextAddrAsString();
				if (cz.nic.extension.dnssecValidator.debugOutput) {
					dump(cz.nic.extension.dnssecValidator.debugPrefix +
					    'Checking browser IP: ' + addr + ';\n');
				}
			}

		}
		// No address obtained.
		if (addr == null) addr = "n/a";

		/*ipbrowser = addr;*/
		if (cz.nic.extension.dnssecValidator.debugOutput) {
			dump(cz.nic.extension.dnssecValidator.debugPrefix 
			    + 'Validation parameters: \"' + dn + '; ' + options
			    + '; ' + nameserver + '; ' + addr + '\"\n');
		}

		cz.nic.extension.dnssecExtHandler.setMode(
		     cz.nic.extension.dnssecExtHandler.DNSSEC_MODE_ACTION);

		// Call DNSSEC validation
		try {
			if (!cz.nic.extension.dnssecValidator.asyncResolveRes) {   
				// Synchronous js-ctypes validation
				var retval = 
				     cz.nic.extension.dnssecLibCore.dnssec_validate_core(
				         dn, options, nameserver, addr);
				cz.nic.extension.dnssecExtResolver.
				    setValidatedData(dn, retval[0],
				        retval[1], addr);
			} else {   
				// Asynchronous js-ctypes validation
				if (cz.nic.extension.dnssecValidator.debugOutput) {
					dump("\n" + cz.nic.extension.dnssecValidator.debugPrefix 
					     + "-------- CALL CORE -- ASYNC RESOLVING ---------\n");
				}
				var queryParams = "validate§" + dn + '§' +
				    options + '§' + nameserver + '§' + addr;
				cz.nic.extension.dnssecworker.
				     postMessage(queryParams);
			}
		} catch (ex) {
			dump(cz.nic.extension.dnssecValidator.debugPrefix 
			    + 'Error: Plugin validation method call failed!\n');
			// Set error mode
			cz.nic.extension.dnssecExtHandler.setMode(
			    cz.nic.extension.dnssecExtHandler.DNSSEC_MODE_ERROR_GENERIC);
			// Reset resolving flag
			cz.nic.extension.dnssecExtPrefs.
			    setBool("resolvingactive", false);
			return;
		}
	},

//---------------------------------------------------------
// Set appropriate security state
//---------------------------------------------------------
setValidatedData:
	function(dn, valres, ipval, addr) {

		var ext = cz.nic.extension.dnssecValidator;

		if (ext.debugOutput) {
			dump(ext.debugPrefix + 'Result: ' + dn + ' : ' +
			    valres + '; IP validator: '+ ipval 
			    + '; IP browser: '+ addr + '\n');
		}

		var res = valres;
		var ipvalidator = ipval;

		var c = cz.nic.extension.dnssecExtNPAPIConst;

		if (res == c.DNSSEC_COT_DOMAIN_BOGUS) {
			if (ext.debugOutput) dump(ext.debugPrefix 
			+ "Unbound return bogus state: Testing why?\n");

			var resolvipv4 = true;
			var resolvipv6 = false;
			var options = 0;

			if (cz.nic.extension.dnssecValidator.debugOutput) {
				options |= c.DNSSEC_FLAG_DEBUG;
			}
			if (resolvipv4) {
				options |= c.DNSSEC_FLAG_RESOLVIPV4;
			}
			if (resolvipv6) {
				options |= c.DNSSEC_FLAG_RESOLVIPV6;
			}
			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.
				    debugPrefix + "NOFWD parameters: " + dn 
				    + "; options: " + options  
				    + "; resolver: nofwd; IP-br: " + addr + ';\n');
			}

			cz.nic.extension.dnssecLibCore.dnssec_validation_deinit_core();
			cz.nic.extension.dnssecLibCore.dnssec_validation_init_core();

			var retval =
			    cz.nic.extension.dnssecLibCore.dnssec_validate_core(
				dn, options, "nofwd", addr);

			if (ext.debugOutput) {
				dump(ext.debugPrefix + 'NOFWD result: ' 
				    + retval[0] + ' : ' + retval[1] +' ;\n');
			}

			if (retval[0] == c.DNSSEC_COT_DOMAIN_BOGUS) {
				if (ext.debugOutput) {
					dump(ext.debugPrefix 
					    + 'Yes, domain name has DNSSEC bogus\n');
				}
				res = c.DNSSEC_COT_DOMAIN_BOGUS;
			} else {
				if (ext.debugOutput) {
					dump(ext.debugPrefix 
					    + "Current resolver does not support DNSSEC!\n");
					dump(ext.debugPrefix + "Results: FWD: " 
					   + res + "; NOFWD: " + restmp +"\n");
				}
				res = c.DNSSEC_RESOLVER_NO_DNSSEC;
			}
		}

		// Set appropriate state if host name does not changed
		// during resolving process (tab has not been switched)
		if (dn == gBrowser.currentURI.asciiHost) {
			cz.nic.extension.dnssecExtHandler.
			    setSecurityState(res, addr, ipvalidator);
		}

		if (ext.debugOutput)
			dump(ext.debugPrefix + ext.debugEndNotice);

		// Resolving has finished
		if (ext.debugOutput) {
			dump(ext.debugPrefix + 'Lock is: ' + 
			     cz.nic.extension.dnssecExtPrefs.getBool(
			     "resolvingactive") + '\n');
			dump(ext.debugPrefix + 'Unlocking section...\n');
		}
		cz.nic.extension.dnssecExtPrefs.setBool(
		     "resolvingactive", false);
		if (ext.debugOutput)
			dump(ext.debugPrefix + 'Lock is: ' + 
			    cz.nic.extension.dnssecExtPrefs.getBool(
			    "resolvingactive") + '\n');
	},

//---------------------------------------------------------
// Return true/false if domain name is in exclude domain list
//---------------------------------------------------------
ExcludeDomainList:
	function(domain) {

		var result = true;
		var DoaminFilter = cz.nic.extension.dnssecExtPrefs.
		    getBool("domainfilter");
		if (DoaminFilter) {
			var DomainSeparator = /[.]+/;
			var DomainArray = domain.split(DomainSeparator);
			var DomainList = cz.nic.extension.dnssecExtPrefs.
			    getChar("domainlist");
			var DomainListSeparators = /[ ,;]+/;
			var DomainListArray = 
			    DomainList.split(DomainListSeparators);
			var i = 0;
			var j = 0;
			var domaintmp = DomainArray[DomainArray.length-1];
			for (i = DomainArray.length-1; i >= 0; i--) {
				for (j = 0; j < DomainListArray.length; j++) {
					if (domaintmp == DomainListArray[j]) {
						return false;
					}
				}
				domaintmp = DomainArray[i-1] + "." + domaintmp;
			}
		}
		return result;
	},

//---------------------------------------------------------
// Called when browser async host lookup completes
//---------------------------------------------------------
onBrowserLookupComplete:
	function(dn, aRecord) {

		var c = cz.nic.extension.dnssecExtNPAPIConst;

		if (this.ExcludeDomainList(dn)) {
			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.debugPrefix
				    + 'Validate this domain? YES\n');
			}

			var resolvipv4 = false; // No IPv4 resolving as default
			var resolvipv6 = false; // No IPv6 resolving as default
			var addr = null;

			if (cz.nic.extension.dnssecValidator.debugOutput)
				dump(cz.nic.extension.dnssecValidator.debugPrefix
				    + cz.nic.extension.dnssecValidator.debugStartNotice);

			// Address list is not empty
			if (aRecord && aRecord.hasMore()) {
				addr = aRecord.getNextAddrAsString();
				// Check IP version
				if (addr.indexOf(":") != -1) {
					// ipv6
					resolvipv6 = true;
				} else if (addr.indexOf(".") != -1) {
					// ipv4
					resolvipv4 = true;
				}
				// No need to check more addresses
				//if (resolvipv4 && resolvipv6) break;
			}

			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.debugPrefix
				     + 'Browser uses IPv4/IPv6 resolving: \"'
				     + resolvipv4 + '/' + resolvipv6 + '\"\n');
			}
			// Resolve IPv4 if no version is desired
			if (!resolvipv4 && !resolvipv6) resolvipv4 = true;
			// Call NPAPI plugin core
			this.dnssecValidate(dn, resolvipv4, resolvipv6, aRecord);
		} else {
			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.debugPrefix + 
				'Validate this domain? NO\n');
			}
			// no DNSSEC validation resolve
			cz.nic.extension.dnssecExtHandler.
			    setSecurityState(c.DNSSEC_OFF);
			// Reset resolving flag
			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.debugPrefix + 'Lock is: ' +
				cz.nic.extension.dnssecExtPrefs.getBool("resolvingactive") + '\n');
				dump(cz.nic.extension.dnssecValidator.debugPrefix +
				'Unlocking section...\n');
			}
			cz.nic.extension.dnssecExtPrefs.setBool("resolvingactive", false);
			if (cz.nic.extension.dnssecValidator.debugOutput) {
				dump(cz.nic.extension.dnssecValidator.debugPrefix + 'Lock is: ' +
				 cz.nic.extension.dnssecExtPrefs.getBool("resolvingactive") + '\n');
			}
		}

	}
};


/* ========================================================================= */
/*
 * Object:
 * Utility class to handle manipulations of the dnssec indicators in the UI
 */
cz.nic.extension.dnssecExtHandler = {
/* ========================================================================= */
// Mode strings used to control CSS display
DNSSEC_MODE_UNBOUND_NO_DATA			: "unboundnodata",
// -3 .Current resolver does not support DNSSEC
DNSSEC_MODE_WRONG_RESOLVER			: "wrongresolver",
// 1. No DNSSEC signature
DNSSEC_MODE_DOMAIN_UNSECURED			: "unsecuredDomain",
// 2. Domain and also connection are secured
DNSSEC_MODE_CONNECTION_DOMAIN_SECURED		: "securedConnectionDomain",
// 3. Domain and also connection are secured but browser's IP address is invalid
DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED	: "securedConnectionDomainInvIPaddr",
// 4. Domain is secured, but it has an invalid signature
DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID		: "invalidDomainSignature",
// 5. No NSEC/NSEC3 for non-existent domain name
DNSSEC_MODE_NODOMAIN_UNSECURED			: "unsecuredNoDomain",
// 6. Connection is secured, but domain name does not exist
DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID		: "securedConnectionNoDomain",
// 7. Non-existent domain is secured, but it has an invalid signature
DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID		: "invalidNoDomainSignature",
// 8. Domain name does not exist but browser got address 
DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID_BAD_IP	: "securedConnectionNoDomainIPaddr",
// Getting security status
DNSSEC_MODE_ACTION	: "actionDnssec",
// Inaction status
DNSSEC_MODE_INACTION	: "inactionDnssec",
// Error or unknown state occured
DNSSEC_MODE_ERROR	: "errorDnssec",
// 0. DNSSEC OFF
DNSSEC_MODE_OFF		: "dnssecOff",
DNSSEC_MODE_ERROR_GENERIC : "genericError",
// Tooltips
DNSSEC_TOOLTIP_SECURED   : "securedTooltip",
DNSSEC_TOOLTIP_UNSECURED : "unsecuredTooltip",
DNSSEC_TOOLTIP_ACTION    : "actionTooltip",
DNSSEC_TOOLTIP_ERROR     : "errorTooltip",
DNSSEC_TOOLTIP_BOGUS     : "bogusTooltip",
DNSSEC_TOOLTIP_OFF       : "offTooltip",
DNSSEC_TOOLTIP_WRONG_RES : "wrongresTooltip",

_asciiHostName : null,
_utf8HostName : null,
ipvalidator : "",
ipbrowser : "",
valstate : 0,

	get _domainPreText () {
		delete this._stringBundle;
		this._stringBundle = document.getElementById("dnssec-strings");

		delete this._domainPreText;
		this._domainPreText = {};

		// DNSSEC error
		this._domainPreText[this.DNSSEC_MODE_ERROR_GENERIC] =
		        this._stringBundle.getString("domain");
		// 0. DNSSEC error
		this._domainPreText[this.DNSSEC_MODE_ERROR] =
		        this._stringBundle.getString("domain");
		// 1. No DNSSEC signature
		this._domainPreText[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
		        this._stringBundle.getString("domain");
		// 2. Domain and also connection are secured
		this._domainPreText[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
		        this._stringBundle.getString("domain");
		// 3. Domain and also connection are secured but browser's IP address is invalid
		this._domainPreText[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
		        this._stringBundle.getString("domain");
		// 4. Domain is secured, but it has an invalid signature
		this._domainPreText[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
		        this._stringBundle.getString("domain");
		// 5. No NSEC/NSEC3 for non-existent domain name
		this._domainPreText[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
		        this._stringBundle.getString("nodomain");
		// 6. Connection is secured, but domain name does not exist
		this._domainPreText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
		        this._stringBundle.getString("nodomain");
		// 7. Non-existent domain is secured, but it has an invalid signature
		this._domainPreText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
		        this._stringBundle.getString("nodomain");
		// 8. Domain name does not exist but browser got address 
		this._domainPreText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID_BAD_IP] =
		        this._stringBundle.getString("nodomain");

		// -1. Validator OFF
		this._domainPreText[this.DNSSEC_MODE_OFF] =
		        this._stringBundle.getString("domain");
		this._domainPreText[this.DNSSEC_MODE_WRONG_RESOLVER] =
		        this._stringBundle.getString("domain");
		return this._domainPreText;
	},

	//set DNSSEC security text
	get _securityText () {
		delete this._stringBundle;
		this._stringBundle = document.getElementById("dnssec-strings");

		delete this._securityText;
		this._securityText = {};

		// DNSSEC error
		this._securityText[this.DNSSEC_MODE_ERROR_GENERIC] =
		        this._stringBundle.getString("dnssecgenericError");
		// 0. DNSSEC error
		this._securityText[this.DNSSEC_MODE_ERROR] =
		        this._stringBundle.getString("0dnssecError");
		// 1. No DNSSEC signature
		this._securityText[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
		        this._stringBundle.getString("1unsecuredDomain");
		// 2. Domain and also connection are secured
		this._securityText[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
		        this._stringBundle.getString("2securedConnectionDomain");
		// 3. Domain and also connection are secured but browser's IP address is invalid
		this._securityText[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
		        this._stringBundle.getString("3securedConnectionDomainInvIPaddr");
		// 4. Domain is secured, but it has an invalid signature
		this._securityText[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
		        this._stringBundle.getString("4invalidDomainSignature");
		// 5. No NSEC/NSEC3 for non-existent domain name
		this._securityText[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
		        this._stringBundle.getString("5unsecuredNoDomain");
		// 6. Connection is secured, but domain name does not exist
		this._securityText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
		        this._stringBundle.getString("6securedConnectionNoDomain");
		// 7. Non-existent domain is secured, but it has an invalid signature
		this._securityText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
		        this._stringBundle.getString("7invalidNoDomainSignature");
		// 8. Domain name does not exist but browser got address 
		this._securityText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID_BAD_IP] =
		        this._stringBundle.getString("8securedConnectionNoDomainIPaddr");

		// -1. Validator OFF
		this._securityText[this.DNSSEC_MODE_OFF] =
		        this._stringBundle.getString("dnsseOff");
		this._securityText[this.DNSSEC_MODE_WRONG_RESOLVER] =
		        this._stringBundle.getString("wrongres");
		//-4
		this._securityText[this.DNSSEC_MODE_UNBOUND_NO_DATA] =
		        this._stringBundle.getString("0dnssecError");

		return this._securityText;
	},

	//set DNSSEC security message detail
	get _securityDetail () {
		delete this._stringBundle;
		this._stringBundle = document.getElementById("dnssec-strings");

		delete this._securityDetail;
		this._securityDetail = {};

		// DNSSEC error
		this._securityDetail[this.DNSSEC_MODE_ERROR_GENERIC] =
		        this._stringBundle.getString("dnssecgenericErrorInfo");
		// 0. DNSSEC error
		this._securityDetail[this.DNSSEC_MODE_ERROR] =
		        this._stringBundle.getString("0dnssecErrorInfo");
		// 1. No DNSSEC signature
		this._securityDetail[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
		        this._stringBundle.getString("1unsecuredDomainInfo");
		// 2. Domain and also connection are secured
		this._securityDetail[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
		        this._stringBundle.getString("2securedConnectionDomainInfo");
		// 3. Domain and also connection are secured but browser's IP address is invalid
		this._securityDetail[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
		        this._stringBundle.getString("3securedConnectionDomainInvIPaddrInfo");
		// 4. Domain is secured, but it has an invalid signature
		this._securityDetail[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
		        this._stringBundle.getString("4invalidDomainSignatureInfo");
		// 5. No NSEC/NSEC3 for non-existent domain name
		this._securityDetail[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
		        this._stringBundle.getString("5unsecuredNoDomainInfo");
		// 6. Connection is secured, but domain name does not exist
		this._securityDetail[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
		        this._stringBundle.getString("6securedConnectionNoDomainInfo");
		// 7. Non-existent domain is secured, but it has an invalid signature
		this._securityDetail[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
		        this._stringBundle.getString("7invalidNoDomainSignatureInfo");
		// 8. Domain name does not exist but browser got address 
		this._securityDetail[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID_BAD_IP] =
		        this._stringBundle.getString("8securedConnectionNoDomainIPaddrInfo");

		// -1. Validator OFF
		this._securityDetail[this.DNSSEC_MODE_OFF] =
		        this._stringBundle.getString("dnsseOffInfo");
		// -2 .Current resolver does not support DNSSEC
		this._securityDetail[this.DNSSEC_MODE_WRONG_RESOLVER] =
		        this._stringBundle.getString("wrongresInfo");
		//-4
		this._securityDetail[this.DNSSEC_MODE_UNBOUND_NO_DATA] =
		        this._stringBundle.getString("unboundnodataInfo");

		return this._securityDetail;
	},

	get _tooltipLabel () {
		delete this._stringBundle;
		this._stringBundle = document.getElementById("dnssec-strings");

		delete this._tooltipLabel;
		this._tooltipLabel = {};

		this._tooltipLabel[this.DNSSEC_TOOLTIP_SECURED] =
		        this._stringBundle.getString("dnssec.tooltip.secured");
		this._tooltipLabel[this.DNSSEC_TOOLTIP_UNSECURED] =
		        this._stringBundle.getString("dnssec.tooltip.unsecured");
		this._tooltipLabel[this.DNSSEC_TOOLTIP_ACTION] =
		        this._stringBundle.getString("dnssec.tooltip.action");
		this._tooltipLabel[this.DNSSEC_TOOLTIP_ERROR] =
		        this._stringBundle.getString("dnssec.tooltip.error");
		this._tooltipLabel[this.DNSSEC_TOOLTIP_BOGUS] =
		        this._stringBundle.getString("dnssec.tooltip.bogus");
		this._tooltipLabel[this.DNSSEC_TOOLTIP_OFF] =
		        this._stringBundle.getString("dnssec.tooltip.off");
		this._tooltipLabel[this.DNSSEC_TOOLTIP_WRONG_RES] =
		        this._stringBundle.getString("dnssec.tooltip.wrongres");
		return this._tooltipLabel;
	},
	get _dnssecPopup () {
		delete this._dnssecPopup;
		return this._dnssecPopup = document.getElementById("dnssec-popup");
	},
	get _dnssecPopupfwd () {
		delete this._dnssecPopupfwd;
		return this._dnssecPopupfwd = document.getElementById("dnssec-popup-fwd");
	},
	get _dnssecBox () {
		delete this._dnssecBox;
		return this._dnssecBox = document.getElementById("dnssec-box");
	},
	get _dnssecPopupContentBox () {
		delete this._dnssecPopupContentBox;
		return this._dnssecPopupContentBox =
		               document.getElementById("dnssec-popup-content-box");
	},
	get _dnssecPopupContentBox2 () {
		delete this._dnssecPopupContentBox2;
		return this._dnssecPopupContentBox2 =
		               document.getElementById("dnssec-popup-content-box2");
	},
	get _dnssecPopupContentBox3 () {
		delete this._dnssecPopupContentBox3;
		return this._dnssecPopupContentBox3 =
		               document.getElementById("dnssec-popup-content-box3");
	},
	get _dnssecPopupContentBox4 () {
		delete this._dnssecPopupContentBox4;
		return this._dnssecPopupContentBox4 =
		               document.getElementById("dnssec-popup-content-box4");
	},
	get _dnssecPopupContentHost () {
		delete this._dnssecPopupContentHost;
		return this._dnssecPopupContentHost =
		               document.getElementById("dnssec-popup-content-host");
	},
	get _dnssecPopupSecLabel () {
		delete this._dnssecPopupSecLabel;
		return this._dnssecPopupSecLabel =
		               document.getElementById("dnssec-popup-security-text");
	},
	get _dnssecPopupSecDetail () {
		delete this._dnssecPopupSecDetail;
		return this._dnssecPopupSecDetail =
		               document.getElementById("dnssec-popup-security-detail");
	},
	get _dnssecPopupfwdDetail () {
		delete this._dnssecPopupfwdDetail;
		return this._dnssecPopupfwdDetail =
		               document.getElementById("dnssec-popup-fwd-text");
	},
	get _dnssecPopupIpBrowser () {
		delete this._dnssecPopupIpBrowser;
		return this._dnssecPopupIpBrowser =
		               document.getElementById("dnssec-popup-ipbrowser-ip");
	},
	get _dnssecPopupIpValidator () {
		delete this._dnssecPopupIpValidator;
		return this._dnssecPopupIpValidator =
		               document.getElementById("dnssec-popup-ipvalidator-ip");
	},

//---------------------------------------------------------
// Build out a cache of the elements that we need frequently
//---------------------------------------------------------
_cacheElements :
	function() {
		delete this._dnssecBox;
		this._dnssecBox = document.getElementById("dnssec-box");
	},

//---------------------------------------------------------
// Set appropriate security state
//---------------------------------------------------------
setSecurityState :
	function(state,addr,ipvalidator) {
		this.ipvalidator = ipvalidator;
		this.ipbrowser = addr;
		this.valstate = state;
		var c = cz.nic.extension.dnssecExtNPAPIConst;

		switch (state) {
			// 1
		case c.DNSSEC_DOMAIN_UNSECURED:
			this.setMode(this.DNSSEC_MODE_DOMAIN_UNSECURED);
			break;
			// 2
		case c.DNSSEC_COT_DOMAIN_SECURED:
			this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED);
			break;
			// 3
		case c.DNSSEC_COT_DOMAIN_SECURED_BAD_IP:
			this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED);
			break;
			// 4
		case c.DNSSEC_COT_DOMAIN_BOGUS:
			this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID);
			break;
			// 5
		case c.DNSSEC_NXDOMAIN_UNSECURED:
			this.setMode(this.DNSSEC_MODE_NODOMAIN_UNSECURED);
			break;
			// 6
		case c.DNSSEC_NXDOMAIN_SIGNATURE_VALID:
			this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID);
			break;
			// 7
		case c.DNSSEC_NXDOMAIN_SIGNATURE_INVALID:
			this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID);
			break;
			// 8
		case c.DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP:
			this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID_BAD_IP);
			break;
			// 0
		case c.DNSSEC_OFF:
			this.setMode(this.DNSSEC_MODE_OFF);
			break;
			//-4
		case c.DNSSEC_UNBOUND_NO_DATA:
			this.setMode(this.DNSSEC_MODE_UNBOUND_NO_DATA);
			break;
			//-3
		case c.DNSSEC_RESOLVER_NO_DNSSEC:
			this.setMode(this.DNSSEC_MODE_WRONG_RESOLVER);
			break;
			// -2
		case c.DNSSEC_ERROR_RESOLVER:
			this.setMode(this.DNSSEC_MODE_ERROR);
			break;
			// -1
		default:
			this.setMode(this.DNSSEC_MODE_ERROR_GENERIC);
			break;
		}
	},

//---------------------------------------------------------
// Determine the security of the domain and connection and, if necessary,
// update the UI to reflect this. Intended to be called by onLocationChange.
//---------------------------------------------------------
checkSecurity :
	function(asciiHost, utf8Host) {

		// Set action state
		//this.setMode(this.DNSSEC_MODE_ACTION);

		// Detect if any resolving is already running...
		if (cz.nic.extension.dnssecExtPrefs.getBool("resolvingactive")) {

			if (cz.nic.extension.dnssecValidator.debugOutput)
				dump(cz.nic.extension.dnssecValidator.debugPrefix
				     + 'Activating resolving timer\n');

			// Cancel running timer if any
			cz.nic.extension.dnssecValidator.timer.cancel();

			// Define timer callback
			cz.nic.extension.dnssecValidator.timer.initWithCallback(
			function() {
				if (cz.nic.extension.dnssecValidator.debugOutput)
					dump(cz.nic.extension.dnssecValidator.debugPrefix
					     + 'Starting timer action\n');
				cz.nic.extension.dnssecValidator.
				     processNewURL(gBrowser.currentURI);
			},
			500,
			Components.interfaces.nsITimer.TYPE_ONE_SHOT);

			// Do not continue to the critical section
			return;
		}

		// ...and lock the critical section-this should be atomic in FF
		if (cz.nic.extension.dnssecValidator.debugOutput) {
			dump(cz.nic.extension.dnssecValidator.debugPrefix
			    + 'Lock is: ' + cz.nic.extension.dnssecExtPrefs.
			         getBool("resolvingactive") + '\n');
			dump(cz.nic.extension.dnssecValidator.debugPrefix
			     + 'Locking section...\n');
		}
		cz.nic.extension.dnssecExtPrefs.setBool("resolvingactive", true);
		if (cz.nic.extension.dnssecValidator.debugOutput)
			dump(cz.nic.extension.dnssecValidator.debugPrefix
			     + 'Lock is: ' + cz.nic.extension.dnssecExtPrefs.
			     getBool("resolvingactive") + '\n');

		this._asciiHostName = asciiHost;
		this._utf8HostName = utf8Host;

		var dnsService = 
		     Components.classes["@mozilla.org/network/dns-service;1"]
		     .getService(Components.interfaces.nsIDNSService);


		var dnsListener = {
		// Called when async host lookup completes
		onLookupComplete:
			function(aRequest, aRecord, aStatus) {
			// Check hostname security state
			cz.nic.extension.dnssecExtResolver.
			      onBrowserLookupComplete(cz.nic.extension.
				    dnssecExtHandler._asciiHostName, aRecord);
			}
		};

		// Thread on which onLookupComplete should be called 
		// after lookup
		var th = Components.classes["@mozilla.org/thread-manager;1"]
		         .getService(Components.interfaces.nsIThreadManager)
		         .mainThread;

		// Get browser's IP address(es) that uses to connect to 
		// the remote site.
		// Uses browser's internal resolver cache
		try {
			// Ci.nsIDNSService.RESOLVE_BYPASS_CACHE
			dnsService.asyncResolve(asciiHost, 0, dnsListener, th);
		} catch(ex) {
			dump(cz.nic.extension.dnssecValidator.debugPrefix
			     + 'Error: Browser\'s async DNS lookup failed!\n');
			// Set error mode
			cz.nic.extension.dnssecExtHandler.
			     setMode(cz.nic.extension.dnssecExtHandler.
				DNSSEC_MODE_ERROR_GENERIC);
			// Reset resolving flag
			cz.nic.extension.dnssecExtPrefs.
			     setBool("resolvingactive", false);
			return;
		}

	},

//---------------------------------------------------------
// Update the UI to reflect the specified mode, which
// should be one of the DNSSEC_MODE_* constants.
//---------------------------------------------------------
setMode :
	function(newMode) {
		if (!this._dnssecBox) {
			// No DNSSEC box means the DNSSEC box is not visible,
			// in which case there's nothing to do.
			return;
		}
		// Close window for these states
		else if (newMode == this.DNSSEC_MODE_ACTION) {
			this.hideDnssecPopup();
		}
		this._dnssecBox.className = newMode;
		this.setSecurityMessages(newMode);
		// Update the popup too, if it's open
		if (this._dnssecPopup.state == "open")
			this.setPopupMessages(newMode);
	},

//---------------------------------------------------------
// Set up the messages for the primary security UI based on the specified mode,
// @param newMode The newly set security mode. Should be one of 
// the DNSSEC_MODE_* constants.
//---------------------------------------------------------
setSecurityMessages :
	function(newMode) {

		var tooltip;

		switch (newMode) {
		// Both domain and connection are secured
		case this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED:
		// Domain and also connection are secured but browser's 
		// IP address is invalid
		case this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED:
			// Both non-existent domain and connection are secured
		case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID:
		case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID_BAD_IP:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_SECURED];
			break;
			// Domain signature is valid
		case this.DNSSEC_MODE_DOMAIN_UNSECURED:
		case this.DNSSEC_MODE_NODOMAIN_UNSECURED:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_UNSECURED];
			break;
		case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID:
		case this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_BOGUS];
			break;
			// Getting security status
		case this.DNSSEC_MODE_ACTION:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_ACTION];
			break;
			// An error occured
		case this.DNSSEC_MODE_ERROR_GENERIC:
		case this.DNSSEC_MODE_ERROR:
		case this.DNSSEC_MODE_UNBOUND_NO_DATA:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_ERROR];
			break;
		case this.DNSSEC_MODE_OFF:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_OFF];
			break;
		case this.DNSSEC_MODE_WRONG_RESOLVER:
			tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_WRONG_RES];
			break;
			// Unknown
		default:
			tooltip = "";
		}
		// Push the appropriate strings out to the UI
		this._dnssecBox.tooltipText = tooltip;
	},

//---------------------------------------------------------
// Show/hide some popup information elements
//---------------------------------------------------------
showAddInfoIP :
	function() {
		document.getElementById("dnssec-popup-ipbrowser-title").style.display = 'block';
		document.getElementById("dnssec-popup-ipbrowser-ip").style.display = 'block';
		document.getElementById("dnssec-popup-ipvalidator-title").style.display = 'block';
		document.getElementById("dnssec-popup-ipvalidator-ip").style.display = 'block';
	},

//---------------------------------------------------------
// Show/hide some popup information elements
//---------------------------------------------------------
hideAddInfoIP :
	function() {
		document.getElementById("dnssec-popup-ipbrowser-title").style.display = 'none';
		document.getElementById("dnssec-popup-ipbrowser-ip").style.display = 'none';
		document.getElementById("dnssec-popup-ipvalidator-title").style.display = 'none';
		document.getElementById("dnssec-popup-ipvalidator-ip").style.display = 'none';
	},

//---------------------------------------------------------
// Show/hide some popup information elements
//---------------------------------------------------------
showAddInfo :
	function(id) {
		document.getElementById(id).style.display = 'block';
		document.getElementById("dnssec-link").style.display = 'none';
		document.getElementById("dnssec-popup-homepage").style.display = 'block';
		if (this.valstate == cz.nic.extension.dnssecExtNPAPIConst.DNSSEC_COT_DOMAIN_SECURED_BAD_IP ||
			this.valstate == cz.nic.extension.dnssecExtNPAPIConst.DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP) {
			this.showAddInfoIP();
		}
	},

//---------------------------------------------------------
// Show/hide some popup information elements
//---------------------------------------------------------
hideAddInfo :
	function() {
		document.getElementById("dnssec-popup-security-detail").style.display = 'none';
		document.getElementById("dnssec-link").style.display = 'block';
		document.getElementById("dnssec-popup-homepage").style.display = 'none';
		if (this.valstate == cz.nic.extension.dnssecExtNPAPIConst.DNSSEC_COT_DOMAIN_SECURED_BAD_IP ||
			this.valstate == cz.nic.extension.dnssecExtNPAPIConst.DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP) {
			this.hideAddInfoIP();
		}
	},

//--------------------------------------------------------
// Set up the title and content messages for the security message popup,
// based on the specified mode.
// @param newMode The newly set security mode. Should be one of the 
// DNSSEC_MODE_* constants. 
//---------------------------------------------------------
setPopupMessages :
	function(newMode) {

		this._dnssecPopup.className = newMode;
		this._dnssecPopupContentBox.className = newMode;
		this._dnssecPopupContentBox2.className = newMode;
		this._dnssecPopupContentBox3.className = newMode;
		this._dnssecPopupContentBox4.className = newMode;
		// Set the static strings up front
		this._dnssecPopupSecLabel.textContent = 
		    this._domainPreText[newMode] + " " + this._utf8HostName
		    + " " + this._securityText[newMode];
		this._dnssecPopupSecDetail.textContent =
		    this._securityDetail[newMode];

		if (this.valstate == cz.nic.extension.dnssecExtNPAPIConst.
			    DNSSEC_COT_DOMAIN_SECURED_BAD_IP ||
			this.valstate == cz.nic.extension.dnssecExtNPAPIConst.
			    DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP) {
			this._dnssecPopupIpBrowser.textContent = this.ipbrowser;
			if (this.ipvalidator=="") this.ipvalidator="n/a";
			this._dnssecPopupIpValidator.textContent = 
			    this.ipvalidator;
		} else {
			this.hideAddInfoIP();
		}

		//dump(this._dnssecPopupSecDetail.textContent);
		// Push the appropriate strings out to the UI
		this._dnssecPopupContentHost.textContent = this._utf8HostName;

		var idnService = 
		    Components.classes["@mozilla.org/network/idn-service;1"]
		    .getService(Components.interfaces.nsIIDNService);

		var tooltipName;

		if (idnService.isACE(this._utf8HostName)) {
			// Encode to UTF-8 if IDN domain name is not in
			// browser's whitelist.
			// See "network.IDN.whitelist.*"
			tooltipName = 
			    idnService.convertACEtoUTF8(this._utf8HostName);
		} else if (idnService.isACE(this._asciiHostName)) {
			// Use punycoded name
			tooltipName = this._asciiHostName;
		} else {
			tooltipName = "";
		}

		this._dnssecPopupContentHost.tooltipText = tooltipName;
	},

//---------------------------------------------------------
// Hide dnssec popup forwarding info
//---------------------------------------------------------
hideDnssecPopup :
	function() {
		// hide add info message
		this.hideAddInfo();
		this._dnssecPopup.hidePopup();
	},

//---------------------------------------------------------
// Hide dnssec popup forwarding info
//---------------------------------------------------------
hideDnssecPopupfwd :
	function() {
		// hide add info message
		this._dnssecPopupfwd.hidePopup();
	},

//---------------------------------------------------------
// Show dnssec popup forwarding info
//---------------------------------------------------------
showDnssecFwdInfo :
	function() {
		// Make sure that the display:none style we set in xul is
		// removed now that the popup is actually needed
		this._dnssecPopupfwd.hidden = false;

		delete this._stringBundle;
		this._stringBundle = document.getElementById("dnssec-strings");
		this._dnssecPopupfwdDetail.textContent = 
		     this._stringBundle.getString("dnssecfwdLabel");
		// Now open the popup, anchored off the primary chrome element
		this._dnssecPopupfwd.openPopup(this._dnssecBox,
		    'after_end',-10,0);
	},

//---------------------------------------------------------
// Hide dnssec popup forwarding info
//---------------------------------------------------------
hideDnssecFwdInfo:
	function() {
		this._dnssecPopupfwd.hidden = true;
	},

//---------------------------------------------------------
// Click handler for the dnssec-box element in primary chrome.
//---------------------------------------------------------
handleDnssecButtonEvent :
	function(event) {

		event.stopPropagation();

		if ((event.type == "click" && event.button != 0) ||
		                (event.type == "keypress" && event.charCode 
				    != KeyEvent.DOM_VK_SPACE &&
				    event.keyCode != KeyEvent.DOM_VK_RETURN)) {
			 // Left click, space or enter only
			return;
		}
		// No popup window while...
		// getting security status
		if (this._dnssecBox && (this._dnssecBox.className 
		     == this.DNSSEC_MODE_ACTION )) {
			return;
		}
		// hide add info message
		this.hideAddInfo();
		// Make sure that the display:none style we set in xul is 
		// removed now that the popup is actually needed
		this._dnssecPopup.hidden = false;

		// Update the popup strings
		this.setPopupMessages(this._dnssecBox.className);
		//dump('Open popopu...\n');
		// Now open the popup, anchored off the primary chrome element
		this._dnssecPopup.openPopup(this._dnssecBox,'after_end',-10,0);
	}
}
