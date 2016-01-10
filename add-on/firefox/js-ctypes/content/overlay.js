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


/* Define our namespace for all componets */
if(!cz) var cz={};
if(!cz.nic) cz.nic={};
if(!cz.nic.extension) cz.nic.extension={};

Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/AddonManager.jsm");

/* ========================================================================= */
/*
 * Class: Window location changed, also happens on changing tabs
 */
cz.nic.extension.validatorExtUrlBarListener = {
/* ========================================================================= */
onLocationChange:
	function(aWebProgress, aRequest, aLocationURI) {
		//dump('Browser: onLocationChange()\n');
		cz.nic.extension.dnssecValidator.processNewURL(aLocationURI);
		var uri = window.gBrowser.currentURI;
		cz.nic.extension.tlsaValidator.processNewURL(aRequest, uri);
	},

onSecurityChange:
	function(aWebProgress, aRequest, aState) {
		//dump('Browser: onSecurityChange(' +aState + ')\n');
		var uri = window.gBrowser.currentURI;
		cz.nic.extension.tlsaValidator.processNewURL(aRequest, uri);
	},

onStateChange:
	function(aWebProgress, aRequest, aStateFlags, aStatus) {
		//dump('Browser: onStateChange\n');
	},

onProgressChange:
	function(aWebProgress, aRequest,
	aCurSelfProgress, aMaxSelfProgress,
	aCurTotalProgress, aMaxTotalProgress) {
		//dump('Browser: onProgressChange()\n');
	},

onStatusChange:
	function(aWebProgress, aRequest, aStatus, aMessage) {
		//dump('Browser: onStatusChange()\n');
	}
};


/* ========================================================================= */
/*
 * Class: Observe preference changes of extension
 */
cz.nic.extension.validatorExtPrefObserver = {
/* ========================================================================= */
_branch: null,


// Add the preference service observer
register:
	function() {
		var prefService = 
		    Components.classes["@mozilla.org/preferences-service;1"]
		.getService(Components.interfaces.nsIPrefService);
		this._branch = 
		    prefService.getBranch(cz.nic.extension.
		        dnssecExtPrefs.prefBranch);
		this._branch.QueryInterface(Components.interfaces.nsIPrefBranch);
		this._branch.addObserver("", this, false);
	},

// Remove the preference service observer
unregister:
	function() {
		if (!this._branch) return;
		this._branch.removeObserver("", this);
	},

// Observe some parameter changes and set actions
observe:
	function(aSubject, aTopic, aData) {
		if (aTopic != "nsPref:changed") return;
		// aSubject is the nsIPrefBranch we're observing 
		// (after appropriate QI)
		// aData is the name of the pref that's been changed 
		// (relative to aSubject)
		switch (aData) {
		// Change debugging to stdout
		case "dnssecdebug":
			cz.nic.extension.dnssecValidator.getDebugOutputFlag();
			break;
		// Change debugging to stdout
		case "danedebug":
			cz.nic.extension.tlsaValidator.getDebugOutputFlag();
			break;
		// Change sync/async resolving
		case "asyncresolve":
			cz.nic.extension.dnssecValidator.getAsyncResolveFlag();
			break;
		// Change popup-window fore/background color
		case "popupfgcolor":
		case "popupbgcolor":
			cz.nic.extension.dnssecValidator.getPopupColors();
			break;
		default:
			break;
		}
	}
};
