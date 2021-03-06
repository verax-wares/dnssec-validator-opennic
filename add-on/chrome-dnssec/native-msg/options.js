/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator 2.x Add-on.

DNSSEC Validator 2.x Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2.x Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.x Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */


var defaultResolver = "nofwd";
var defaultCustomResolver = "217.31.204.130";
var DNSSEC = "DNSSEC: ";
var debuglogout = false;
var initplugin = false;
var port = null;


//--------------------------------------------------------
// Set string in the page element
//--------------------------------------------------------
function addText(id, str){

	if (document.createTextNode){
		var tn = document.createTextNode(str);
		document.getElementById(id).appendChild(tn);
	}
}


//--------------------------------------------------------
// text bool value from LocalStorage to bool
//--------------------------------------------------------
function StringToBool(value) {

	if (value == undefined) return false;
	else if (value == "false") return false;
	else if (value == "true") return true;
	else return false;
}


//--------------------------------------------------------
// check correct format of IP addresses in the textarea
//--------------------------------------------------------
function test_ip(ip) {

	var expression = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(@\d{1,5})?\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?(@\d{1,5})?\s*$))/;

	var match = ip.match(expression);
	return match != null;
}


//--------------------------------------------------------
// check correct format of IP addresses in the text area
//--------------------------------------------------------
function checkOptdnsserveraddr(str) {

	var n = str.split(" ");
	var c = 0;
	for(c = 0; c < n.length; c++) {
		if (!test_ip(n[c])) {
			return false;
		} //if
	} //for
	return true;
}


//--------------------------------------------------------
// check correct format of domain and TLD in the text area
//--------------------------------------------------------
function checkdomainlist() {

	var str = document.getElementById("domainlist").value;
	var match = str.match(/^[a-z0-9.-]+(, [a-z0-9.-]+)*$/);
	return match != null;
}


//--------------------------------------------------------
// Cancel settings without saving on the local storage
//--------------------------------------------------------
function cancelOptions() {

	window.close();
}


//--------------------------------------------------------
// Save settings on the local storage
//--------------------------------------------------------
function saveOptions() {

	var radiogroup = document.dnssecSettings.resolver;
	var resolver;
	for (var i = 0; i < radiogroup.length; i++) {
		var child = radiogroup[i];
		if (child.checked == true) {
			resolver = child.value;
			break;
		}
	}

	localStorage["dnssecResolver"] = resolver;
	localStorage["dnssecCustomResolver"] = document.dnssecSettings.customResolver.value;
	localStorage["DebugOutput"] = document.dnssecSettings.DebugOutput.checked;
	localStorage["domainfilteron"] = document.dnssecSettings.domainfilteron.checked;
	localStorage["domainlist"] = document.dnssecSettings.domainlist.value;
	localStorage["deldnssecctx"] = true;
	
	if (initplugin) {	
		port.postMessage("finish");
	}

	document.write("<div>Settings were saved...</div>");
	document.write("<div>Please, close this window...Thanks</div>");
	window.close();
}


//--------------------------------------------------------
// reset elements on the settings page
//--------------------------------------------------------
function resetTesting() {

	var elems = document.getElementsByTagName('input');
	var len = elems.length;

	for (var i = 0; i < len; i++) {
    		elems[i].disabled = false;
	}

	document.getElementById("actionimg").style.display = 'none';
	document.getElementById("testbutton").style.display = 'block';
	document.getElementById("testbutton").value = 
	    chrome.i18n.getMessage("testbutton");
}


//--------------------------------------------------------
// Callback to handle native message response.
//--------------------------------------------------------
function handle_test_response(resp) {

	var retval = resp.split("~");

	switch (retval[0]) {

	case "initialiseRet":
		initplugin = true;
		if (debuglogout) {
			console.log(DNSSEC
			    + "Load DNSSEC native messaging core");
		}
		break;

	case "validateRet":
		var testnic = retval[2];

		if (debuglogout) {
			console.log(DNSSEC + "Received response:" + resp + " " + testnic);
		}

		if (testnic == 2) {
			document.getElementById("messageok").style.display = 'block';
			document.getElementById("messagebogus").style.display = 'none';
			document.getElementById("messageerror").style.display = 'none';
			document.getElementById("messageip").style.display = 'none';
		} else if (testnic == 4) {
			document.getElementById("messageok").style.display = 'none';
			document.getElementById("messagebogus").style.display = 'block';
			document.getElementById("messageerror").style.display = 'none';
			document.getElementById("messageip").style.display = 'none';
		} else {
			document.getElementById("messageok").style.display = 'none';
			document.getElementById("messagebogus").style.display = 'none';
			document.getElementById("messageerror").style.display = 'block';
			document.getElementById("messageip").style.display = 'none';
		}

		resetTesting();
		break;
	default:
		break;
	}
}


//--------------------------------------------------------
// test on DNSSEC support
//--------------------------------------------------------
function testdnssec() {

	var elems = document.getElementsByTagName('input');
	var len = elems.length;

	for (var i = 0; i < len; i++) {
		elems[i].disabled = true;
	}

	document.getElementById("messageok").style.display = 'none';
	document.getElementById("messagebogus").style.display = 'none';
	document.getElementById("messageerror").style.display = 'none';
	document.getElementById("messageip").style.display = 'none';

	document.getElementById("testbutton").style.display = 'none';
	document.getElementById("actionimg").style.display = 'block';

	var nameserver = "217.31.204.130";
	var options = 7;
	var testnic = 0;
	var ip = false;
	var dn = "www.nic.cz";
	var addr = "217.31.205.50";
	var chioce = 0;
	var tmp = document.dnssecSettings.customResolver.value;
	var radiogroup = document.dnssecSettings.resolver;

	for (var i = 0; i < radiogroup.length; i++) {
		var child = radiogroup[i];
		if (child.checked == true) {
			switch (i) {
			case 0: // System setting
				nameserver = "sysresolver";
				chioce = 0;
				break;
			case 1: // Custom
				chioce = 1;
				if (!checkOptdnsserveraddr(tmp)) {
					ip = true;
				} else {
					nameserver = tmp;
				}
				break;
			case 2: // NOFWD
				chioce = 2;
				nameserver = "nofwd";
				options = 5;
				break;
			}
		}
	}

	if (ip) {

		var elems = document.getElementsByTagName('input');
		var len = elems.length;

		for (var i = 0; i < len; i++) {
			elems[i].disabled = false;
		}

		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none'
		document.getElementById("messageip").style.display = 'block';
		document.getElementById("actionimg").style.display = 'none';
		document.getElementById("testbutton").style.display = 'block';	
		document.getElementById("testbutton").value = 
			chrome.i18n.getMessage("testbutton");
	} else {

		port.postMessage("initialise");

		var queryParams = "validate~" + dn + '~' + options + '~' +
		    nameserver + '~' + addr + '~notab';

		if (debuglogout) {
			console.log(DNSSEC + queryParams);
		}

		port.postMessage(queryParams);
	}
}


//--------------------------------------------------------
// help function for clear DNSSEC localestorage, not use.
//--------------------------------------------------------
function eraseOptions() {

	localStorage.removeItem("dnssecResolver");
	localStorage.removeItem("dnssecCustomResolver");
	localStorage.removeItem("DebugOutput");
	localStorage.removeItem("deldnssecctx");
	localStorage.removeItem("domainlist");
	localStorage.removeItem("domainfilteron");
	location.reload();
}


//--------------------------------------------------------
// Refresh some elements on the page
//--------------------------------------------------------
function RefreshExclude() {

	var ischecked = document.getElementById("domainfilteron").checked;
	document.getElementById("domainlist").disabled = !ischecked;
	if (ischecked) {
		document.getElementById("domainlist").style.color = 'black';
		document.getElementById("filtertext").style.color = 'black';
	} else {
		document.getElementById("domainlist").style.color = 'grey';
		document.getElementById("filtertext").style.color = 'grey';
	}
}


//--------------------------------------------------------
// Replaces onclick for the option buttons
//--------------------------------------------------------
window.onload = function(){

	document.querySelector('input[id="savebutton"]').onclick = saveOptions;
	document.querySelector('input[id="testbutton"]').onclick = testdnssec;
	document.querySelector('input[id="cancelbutton"]').onclick = cancelOptions;
	var domainfilteron = document.querySelectorAll('input[type=checkbox][id=domainfilteron]');
	domainfilteron[0].onchange = RefreshExclude;
}

//--------------------------------------------------------
// show DNSSEC text about resover settings
//--------------------------------------------------------
function testinfodisplay(state){

	if (state == 0) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none'
		document.getElementById("messageip").style.display = 'block';
	}
	else if (state == 1) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'block';
		document.getElementById("messageip").style.display = 'none';
	}
	else if (state == 2) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'block';
		document.getElementById("messageerror").style.display = 'none';
		document.getElementById("messageip").style.display = 'none';
	}
	else if (state == 3) {
		document.getElementById("messageok").style.display = 'block';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none';
		document.getElementById("messageip").style.display = 'none';
	}
	else {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none';
		document.getElementById("messageip").style.display = 'none';
	}
}


//--------------------------------------------------------
// Settings window initialization
//--------------------------------------------------------
window.addEventListener('load',function(){

	debuglogout = StringToBool(localStorage["DebugOutput"]);

	resultRegexp = /\?([^?,]+),([^,]+),([^,]+)$/;
	matches = resultRegexp.exec(document.location.href);
	state = matches[1];
	choice = matches[2];
	resolver = matches[3];
	unescape(resolver);
	testinfodisplay(state);
	addText("preftitle", chrome.i18n.getMessage("preftitle"));
	addText("prefresolver", chrome.i18n.getMessage("prefresolver"));
	addText("legend", chrome.i18n.getMessage("legend"));
	addText("resolver0", chrome.i18n.getMessage("resolver0"));
	addText("resolver3", chrome.i18n.getMessage("resolver3"));
	addText("resolver4", chrome.i18n.getMessage("resolver4"));
	addText("messageok", chrome.i18n.getMessage("messageok"));
	addText("messagebogus", chrome.i18n.getMessage("messagebogus"));
	addText("messageerror", chrome.i18n.getMessage("messageerror"));
	addText("messageip", chrome.i18n.getMessage("messageip"));
	addText("groupboxfilter", chrome.i18n.getMessage("groupboxfilter"));
	addText("usefilter", chrome.i18n.getMessage("usefilter"));
	addText("filtertext", chrome.i18n.getMessage("filtertext"));
	addText("debugoutputtext", chrome.i18n.getMessage("debugoutputtext"));
	document.getElementById("testbutton").value=chrome.i18n.getMessage("testbutton");
	document.getElementById("savebutton").value=chrome.i18n.getMessage("savebutton");
	document.getElementById("cancelbutton").value=chrome.i18n.getMessage("cancelbutton");

	if (state == 4) {
		var dnssecResolver = localStorage["dnssecResolver"];
		// IP address of custom resolver
		var dnssecCustomResolver = localStorage["dnssecCustomResolver"];
		// debug output of resolving to stderr
		var DebugOutput = localStorage["DebugOutput"];

		var domainfilteron = localStorage["domainfilteron"];
		var domainlist = localStorage["domainlist"];
		if (domainlist == undefined) {
			domainlist = "";
		}
		if (dnssecResolver == undefined) {
			dnssecResolver = defaultResolver;
		}
		if (dnssecCustomResolver == undefined) {
			dnssecCustomResolver = defaultCustomResolver;
		}

		localStorage["deldnssecctx"] = false;

		// OMG local storage has everything as text
		DebugOutput = (DebugOutput == undefined || DebugOutput == "false") ? false : true;
		document.dnssecSettings.customResolver.value = dnssecCustomResolver;
		document.dnssecSettings.DebugOutput.checked = DebugOutput;
		document.dnssecSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
		document.dnssecSettings.domainfilteron.checked = domainfilteron;
		document.getElementById("domainlist").disabled = !domainfilteron;
		if (domainfilteron) {
			document.getElementById("domainlist").style.color = 'black';
			document.getElementById("filtertext").style.color = 'black';
		} else {
			document.getElementById("domainlist").style.color = 'grey';
			document.getElementById("filtertext").style.color = 'grey';
		}
		var radiogroup = document.dnssecSettings.resolver;
		for (var i = 0; i < radiogroup.length; i++) {
			var child = radiogroup[i];
				if (child.value == dnssecResolver) {
				    child.checked = "true";
				    break;
			}
		}
	} else {
		localStorage["deldnssecctx"] = false;

		document.dnssecSettings.customResolver.value = unescape(resolver);
		var radiogroup = document.dnssecSettings.resolver;
		var child = radiogroup[choice];
		child.checked = "true";
		var domainfilteron = localStorage["domainfilteron"];
		var domainlist = localStorage["domainlist"];
		if (domainlist == undefined) {
			domainlist = "";
		}
		var DebugOutput = localStorage["DebugOutput"];
		document.dnssecSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
		document.dnssecSettings.domainfilteron.checked = domainfilteron;
		document.getElementById("domainlist").disabled = !domainfilteron;
		if (domainfilteron) {
			document.getElementById("domainlist").style.color = 'black';
			document.getElementById("filtertext").style.color = 'black';
		} else {
			document.getElementById("domainlist").style.color = 'grey';
			document.getElementById("filtertext").style.color = 'grey';
		}

		DebugOutput = (DebugOutput == undefined || DebugOutput == "false") ? false : true;
		document.dnssecSettings.DebugOutput.checked = DebugOutput;
	}

	document.getElementById("testbutton").disabled = true;

	port = chrome.runtime.connectNative("cz.nic.validator.dnssec");
	port.onMessage.addListener(handle_test_response);
	port.onDisconnect.addListener(function() {
		if (debuglogout) {
			console.log(DNSSEC + "Helper host disconnected.");
		}
	});

	port.postMessage("initialise");

	setTimeout(function() {
		if (!initplugin) {
			document.getElementById("messageerror").innerHTML = "";
			addText("messageerror", chrome.i18n.getMessage("dnssecnopluginInfo"));
			document.getElementById("testbutton").style.display = 'none';
			document.getElementById("messageerror").style.display = 'block';
			if (debuglogout) {
				console.log(DNSSEC
			 	   + "Cannot load DNSSEC native messaging core!");
			}
		} else {
			document.getElementById("testbutton").disabled = false;
		}
	}, 1000);
});

