<?php
/* (c) Blue Wave Projects and Services 2015-2021. This software is released under the GNU GPL license.

 This is a FAS script providing an example of remote Forward Authentication for openNDS (NDS) on an http web server supporting PHP.

 The following NDS configurations must be set:
 1. fasport: Set to the port number the remote webserver is using (typically port 80)

 2. faspath: This is the path from the FAS Web Root to the location of this FAS script (not from the file system root).
	eg. /nds/fas-aes-https.php

 3. fasremoteip: The remote IPv4 address of the remote server eg. 46.32.240.41

 4. fasremotefqdn: The fully qualified domain name of the remote web server.
	This is required in the case of a shared web server (ie. a server that hosts multiple domains on a single IP),
	but is optional for a dedicated web server (ie. a server that hosts only a single domain on a single IP).
	eg. onboard-wifi.net

 5. faskey: Matching $key as set in this script (see below this introduction).
	This is a key phrase for NDS to encrypt the query string sent to FAS.
	It can be any combination of A-Z, a-z and 0-9, up to 16 characters with no white space.
	eg 1234567890

 6. fas_secure_enabled:  set to level 3
	The NDS parameters: clientip, clientmac, gatewayname, client token, gatewayaddress, authdir and originurl
	are encrypted using fas_key and passed to FAS in the query string.

	The query string will also contain a randomly generated initialization vector to be used by the FAS for decryption.

	The "php-cli" package and the "php-openssl" module must both be installed for fas_secure level 2.

 openNDS does not have "php-cli" and "php-openssl" as dependencies, but will exit gracefully at runtime if this package and module
 are not installed when fas_secure_enabled is set to level 3.

 The FAS must use the initialisation vector passed with the query string and the pre shared faskey to decrypt the required information.

 The remote web server (that runs this script) must have the "php-openssl" module installed (standard for most hosting services).

 This script requires the client user to enter their Fullname and email address. This information is stored in a log file kept
 in the same folder as this script.

 This script requests the client CPD to display the NDS avatar image directly from Github.

 This script displays an example Terms of Service. You should modify this for your local legal juristiction.

 The script is provided as a fully functional alternative to the basic NDS splash page.
 In its present trivial form it does not do any verification, but serves as an example for customisation projects.

 The script retreives the clientif string sent from NDS and displays it on the login form.
 "clientif" is of the form [client_local_interface] [remote_meshnode_mac] [local_mesh_if]
 The returned values can be used to dynamically modify the login form presented to the client,
 depending on the interface the client is connected to.
 eg. The login form can be different for an ethernet connection, a private wifi, a public wifi or a remote mesh network zone.

*/

// Allow immediate flush to browser
if (ob_get_level()){ob_end_clean();}

//force redirect to secure page
//if(empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] == "off"){
//    $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
//    header('HTTP/1.1 301 Moved Permanently');
//    header('Location: ' . $redirect);
//    exit();
//}

// setup some defaults
date_default_timezone_set("UTC");
$client_zone=$fullname=$email=$invalid="";
$cipher="AES-256-CBC";
$me=$_SERVER['SCRIPT_NAME'];

if (file_exists("/etc/config/opennds")) {
	$logpath="/tmp/";
} elseif (file_exists("/etc/opennds/opennds.conf")) {
	$logpath="/run/";
} else {
	$logpath="";
}

###############################################################################
#
# Set the pre-shared key. This MUST be the same as faskey in the openNDS config
#
$key="1234567890";
#
###############################################################################

#############################################################################################################
#
# Configure Quotas - Time, Data and Data Rate
#
#############################################################################################################
# Set the session length(minutes), upload/download quotas(kBytes), upload/download rates(kbits/s)
# and custom string to be sent to the BinAuth script.
# Upload and download quotas are in kilobytes.
# If a client exceeds its upload or download quota it will be deauthenticated on the next cycle of the client checkinterval.
# (see openNDS config for checkinterval)

# Client Upload and Download Rates are the average rates a client achieves since authentication 
# If a client exceeds its set upload or download rate it will be deauthenticated on the next cycle of the client checkinterval.

# The following variables are set on a client by client basis. If a more sophisticated client credential verification was implemented,
# these variables could be set dynamically.
#
# In addition, choice of the values of these variables can be determined, based on the interface used by the client
# (as identified by the clientif parsed variable). For example, a system with two wireless interfaces such as "members" and "guests". 

# A value of 0 means no limit
$sessionlength=0; // minutes (1440 minutes = 24 hours)
$uploadrate=0; // kbits/sec (500 kilobits/sec = 0.5 Megabits/sec)
$downloadrate=0; // kbits/sec (1000 kilobits/sec = 1.0 Megabits/sec)
$uploadquota=0; // kBytes (500000 kiloBytes = 500 MegaBytes)
$downloadquota=0; // kBytes (1000000 kiloBytes = 1 GigaByte)

#############################################################################################################
#
# Custom string to be sent to Binauth
#
# Define a custom string that will be sent to BunAuth for additional local post authentication processing.
# Binauth is most useful for writing a local log on the openNDS router
$custom="Optional Custom data for BinAuth";

#############################################################################################################
#
# Send The Auth List when requested by openNDS
#
# When a client was verified, their parameters were added to the "auth list"
# The auth list is sent to NDS when it authmon requests it.
#
# auth_get:
#
# value "list" sends the list and deletes each client entry that it finds
#
# value "view" just sends the list, this is the default value for authmon and allows upstream processing here
#
#############################################################################################################

if (isset($_POST["auth_get"])) {

	$acklist=base64_decode($_POST["payload"]);

	if (isset($_POST["gatewayhash"])) {
		$gatewayhash=$_POST["gatewayhash"];
	} else {
		# invalid call, so:
		exit(0);
	}

	if (! file_exists("$logpath"."$gatewayhash")) {
		# no clients waiting, so:
		exit(0);
	}

	if ($_POST["auth_get"] == "clear") {
		$auth_list=scandir("$logpath"."$gatewayhash");
		array_shift($auth_list);
		array_shift($auth_list);

		foreach ($auth_list as $client) {
			unlink("$logpath"."$gatewayhash/$client");
		}
		# Stale entries cleared, so:
		exit(0);
	}

	# Set default empty authlist:
	$authlist="*";

	if ($_POST["auth_get"] == "list") {
		$auth_list=scandir("$logpath"."$gatewayhash");
		array_shift($auth_list);
		array_shift($auth_list);

		foreach ($auth_list as $client) {
			$clientauth=file("$logpath"."$gatewayhash/$client");
			$authlist=$authlist." ".rawurlencode(trim($clientauth[0]));
			unlink("$logpath"."$gatewayhash/$client");
		}
		echo trim("$authlist");

	} else if ($_POST["auth_get"] == "view") {

		if ($acklist != "none") {
			$acklist_r=explode("\n",$acklist);

			foreach ($acklist_r as $client) {
				$client=ltrim($client, "* ");

				if ($client != "") {
					if (file_exists("$logpath"."$gatewayhash/$client")) {
						unlink("$logpath"."$gatewayhash/$client");
					}
				}
			}
			echo "ack";
		} else {
			$auth_list=scandir("$logpath"."$gatewayhash");
			array_shift($auth_list);
			array_shift($auth_list);

			foreach ($auth_list as $client) {
				$clientauth=file("$logpath"."$gatewayhash/$client");
				$authlist=$authlist." ".rawurlencode(trim($clientauth[0]));
			}
		echo trim("$authlist");
		}
	}
	exit(0);
}
#############################################################################################################

// Service requests for remote image
if (isset($_GET["get_image"])) {
	$url=$_GET["get_image"];
	$imagetype=$_GET["imagetype"];
	get_image($url, $imagetype);
	exit(0);
}

// define the image to display
// eg. https://avatars1.githubusercontent.com/u/62547912 is the openNDS Portal Lens Flare
$imageurl="https://avatars1.githubusercontent.com/u/62547912";
$imagetype="png";
$scriptname=basename($_SERVER['SCRIPT_NAME']);
$imagepath=htmlentities("$scriptname?get_image=$imageurl&imagetype=$imagetype");

// Get the query string components
if (isset($_GET['status'])) {
	$redir=$_GET['redir'];
	$redir_r=explode("fas=", $redir);
	$fas=$redir_r[1];
	$iv=$_GET['iv'];
} else if (isset($_GET['fas']))  {
	$fas=$_GET['fas'];
	$iv=$_GET['iv'];
} else {
	exit(0);
}

####################################################################################################################################
#
#	Decrypt and Parse the querystring
#
#	Note: $ndsparamlist is an array of parameter names to parse for.
#		Add your own custom parameters to this array as well as to the config file.
#		"admin_email" and "location" are examples of custom parameters.
#
####################################################################################################################################

$ndsparamlist=explode(" ", "clientip clientmac gatewayname version hid gatewayaddress gatewaymac authdir originurl clientif admin_email location");

if (isset($_GET['fas']) and isset($_GET['iv']))  {
	$string=$_GET['fas'];
	$iv=$_GET['iv'];
	$decrypted=openssl_decrypt( base64_decode( $string ), $cipher, $key, 0, $iv );
	$dec_r=explode(", ",$decrypted);

	foreach ($ndsparamlist as $ndsparm) {
		foreach ($dec_r as $dec) {
			@list($name,$value)=explode("=",$dec);
			if ($name == $ndsparm) {
				$$name = $value;
				break;
			}
		}
	}
}
####################################################################################################################################
####################################################################################################################################

// Work out the client zone:
$client_zone_r=explode(" ",trim($clientif));

if ( ! isset($client_zone_r[1])) {
	$client_zone="LocalZone:".$client_zone_r[0];
} else {
	$client_zone="MeshZone:".str_replace(":","",$client_zone_r[1]);
}

#################################################################################
# Create auth list directory for this gateway
# This list will be sent to NDS when it requests it.
#################################################################################

$gwname=hash('sha256', trim($gatewayname));

if (!file_exists("$logpath"."$gwname")) {
	mkdir("$logpath"."$gwname", 0700);
}

#######################################################
//Start Outputting the requested responsive page:
#######################################################

//splash_header();

if (isset($_GET["terms"])) {
	// ToS requested
	display_terms();
	//footer();
} elseif (isset($_GET["status"])) {
	// The status page is triggered by a client if already authenticated by openNDS (eg by clicking "back" on their browser)
	status_page();
	//footer();
} elseif (isset($_GET["auth"])) {
	# Verification is complete so now wait for openNDS to authenticate the client.
	authenticate_page();
	//footer();
} elseif (isset($_GET["landing"])) {
	// The landing page is served to the client immediately after openNDS authentication, but many CPDs will immediately close
	landing_page();
	//footer();
} else {
	login_page();
	//footer();
}

#############################################################################################################
// Functions:

function get_image($url, $imagetype) {
	header("Content-type: image/$imagetype");
	readfile($url);
}

function authenticate_page() {
	# Display a "logged in" landing page once NDS has authenticated the client.
	# or a timed out error if we do not get authenticated by NDS
	$me=$_SERVER['SCRIPT_NAME'];
	$host=$_SERVER['HTTP_HOST'];
	$clientip=$GLOBALS["clientip"];
	$gatewayname=$GLOBALS["gatewayname"];
	$gatewayaddress=$GLOBALS["gatewayaddress"];
	$gatewaymac=$GLOBALS["gatewaymac"];
	$hid=$GLOBALS["hid"];
	$key=$GLOBALS["key"];
	$clientif=$GLOBALS["clientif"];
	$originurl=$GLOBALS["originurl"];
	$redir=rawurldecode($originurl);
	$sessionlength=$GLOBALS["sessionlength"];
	$uploadrate=$GLOBALS["uploadrate"];
	$downloadrate=$GLOBALS["downloadrate"];
	$uploadquota=$GLOBALS["uploadquota"];
	$downloadquota=$GLOBALS["downloadquota"];
	$gwname=$GLOBALS["gwname"];
	$logpath=$GLOBALS["logpath"];
	$custom=$GLOBALS["custom"];

	$rhid=hash('sha256', trim($hid).trim($key));

	# Construct the client authentication string or "log"
	# Note: override values set earlier if required, for example by testing clientif 
	$log="$rhid $sessionlength $uploadrate $downloadrate $uploadquota $downloadquota ".rawurlencode($custom)."\n";

	$logfile="$logpath"."$gwname/$rhid";

	if (!file_exists($logfile)) {
		file_put_contents("$logfile", "$log");
	}

	echo "Waiting for link to establish....<br>";
	flush();
	$count=0;
	$maxcount=30;

	for ($i=1; $i<=$maxcount; $i++) {
		$count++;
		sleep(1);
		echo "<b style=\"color:red;\">*</b>";

		if ($count == 10) {echo "<br>"; $count=0;}

		flush();

		if (file_exists("$logfile")) {
			$authed="no";
		} else {
			//no list so must be authed
			$authed="yes";
			write_log();
		}

		if ($authed == "yes") {
			echo "<br><b>Authenticated</b><br>";
			landing_page();
			flush();
			break;
		}
	}

	if ($i > $maxcount) {
		unlink("$logfile");
		echo "
			<br>The Portal has timed out<br>You may have to turn your WiFi off and on to reconnect.<br>
			<p>
			Click or tap Continue to try again.
			</p>
			<form>
				<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='".$redir."'\" >
			</form>
		";
	}
}

function thankyou_page() {
	# Output the "Thankyou page" with a continue button
	# You could include information or advertising on this page
	# Be aware that many devices will close the login browser as soon as
	# the client taps continue, so now is the time to deliver your message.

	# You can also send a custom data string to BinAuth. Set the variable $custom to the desired value
	# Max length 256 characters
	$custom="Custom data sent to BinAuth";
	$custom=base64_encode($custom);

	$me=$_SERVER['SCRIPT_NAME'];
	$host=$_SERVER['HTTP_HOST'];
	$fas=$GLOBALS["fas"];
	$iv=$GLOBALS["iv"];
	$clientip=$GLOBALS["clientip"];
	$gatewayname=$GLOBALS["gatewayname"];
	$gatewayaddress=$GLOBALS["gatewayaddress"];
	$gatewaymac=$GLOBALS["gatewaymac"];
	$key=$GLOBALS["key"];
	$hid=$GLOBALS["hid"];
	$clientif=$GLOBALS["clientif"];
	$originurl=$GLOBALS["originurl"];
	$fullname=$_GET["fullname"];
	$email=$_GET["email"];
	$fullname_url=rawurlencode($fullname);
	$auth="yes";

	echo "
		<big-red>
			Thankyou!
		</big-red>
		<br>
		<b>Welcome $fullname</b>
		<br>
		<italic-black>
			Your News or Advertising could be here, contact the owners of this Hotspot to find out how!
		</italic-black>
		<form action=\"$me\" method=\"get\">
			<input type=\"hidden\" name=\"fas\" value=\"$fas\">
			<input type=\"hidden\" name=\"iv\" value=\"$iv\">
			<input type=\"hidden\" name=\"auth\" value=\"$auth\">
			<input type=\"hidden\" name=\"fullname\" value=\"$fullname_url\">
			<input type=\"hidden\" name=\"email\" value=\"$email\">
			<input type=\"submit\" value=\"Continue\" >
		</form>
		<hr>
	";

	read_terms();
	flush();
}

function write_log() {
	# In this example we have decided to log all clients who are granted access
	# Note: the web server daemon must have read and write permissions to the folder defined in $logpath
	# By default $logpath is null so the logfile will be written to the folder this script resides in,
	# or the /tmp directory if on the NDS router

	if (file_exists("/etc/config/opennds")) {
		$logpath="/tmp/";
	} elseif (file_exists("/etc/opennds/opennds.conf")) {
		$logpath="/run/";
	} else {
		$logpath="";
	}

	if (!file_exists("$logpath"."ndslog")) {
		mkdir("$logpath"."ndslog", 0700);
	}

	$me=$_SERVER['SCRIPT_NAME'];
	$script=basename($me, '.php');
	$host=$_SERVER['HTTP_HOST'];
	$user_agent=$_SERVER['HTTP_USER_AGENT'];
	$clientip=$GLOBALS["clientip"];
	$clientmac=$GLOBALS["clientmac"];
	$gatewayname=$GLOBALS["gatewayname"];
	$gatewayaddress=$GLOBALS["gatewayaddress"];
	$gatewaymac=$GLOBALS["gatewaymac"];
	$clientif=$GLOBALS["clientif"];
	$originurl=$GLOBALS["originurl"];
	$redir=rawurldecode($originurl);
	if (isset($_GET["fullname"])) {
		$fullname=$_GET["fullname"];
	} else {
		$fullname="na";
	}

	if (isset($_GET["email"])) {
		$email=$_GET["email"];
	} else {
		$email="na";
	}

	$log=date('Y-m-d H:i:s', $_SERVER['REQUEST_TIME']).
		", $script, $gatewayname, $fullname, $email, $clientip, $clientmac, $clientif, $user_agent, $redir\n";

	if ($logpath == "") {
		$logfile="ndslog/ndslog_log.php";

		if (!file_exists($logfile)) {
			@file_put_contents($logfile, "<?php exit(0); ?>\n");
		}
	} else {
		$logfile="$logpath"."ndslog/ndslog.log";
	}

	@file_put_contents($logfile, $log,  FILE_APPEND );
}

function login_page() {
	$fullname=$email="";
	$me=$_SERVER['SCRIPT_NAME'];
	$fas=$_GET["fas"];
	$iv=$GLOBALS["iv"];
	$clientip=$GLOBALS["clientip"];
	$clientmac=$GLOBALS["clientmac"];
	$gatewayname=$GLOBALS["gatewayname"];
	$gatewayaddress=$GLOBALS["gatewayaddress"];
	$gatewaymac=$GLOBALS["gatewaymac"];
	$clientif=$GLOBALS["clientif"];
	$client_zone=$GLOBALS["client_zone"];
	$originurl=$GLOBALS["originurl"];

	if (isset($_GET["fullname"])) {
		$fullname=ucwords($_GET["fullname"]);
	}

	if (isset($_GET["email"])) {
		$email=$_GET["email"];
	}

	if ($fullname == "" or $email == "") {
		?>
<!doctype html>
<html>

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link href="../pages/tailwind.css" rel="stylesheet">

</head>

<body>
    <div class="h-16"></div>
    <div class="flex max-w-sm mx-auto overflow-hidden bg-white rounded-lg shadow-lg dark:bg-gray-800 lg:max-w-4xl">
        <div class="hidden bg-cover lg:block lg:w-1/2"
            style="background-image:url('https://images.unsplash.com/photo-1606660265514-358ebbadc80d?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=1575&q=80')">
        </div>

        <div class="w-full px-6 py-8 md:px-8 lg:w-1/2">
            <h2 class="text-2xl font-semibold text-center text-gray-700 dark:text-white">WSECURITY</h2>

            <p class="text-xl text-center text-gray-600 dark:text-gray-200">Estas conectado a <?php echo $client_zone; ?></p>

			<?php
			if (! isset($_GET['fas']))  { 
			?>
				<p class="text-xl text-center text-gray-600 dark:text-gray-200">ERROR! Incomplete data passed from NDS</p>
			<?php
			}
			?>

            <a href="#"
                class="flex items-center justify-center mt-4 text-gray-600 rounded-lg shadow-md dark:bg-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600">
                <div class="px-4 py-3">
                    <svg class="w-6 h-6" viewBox="0 0 40 40">
                        <path
                            d="M36.3425 16.7358H35V16.6667H20V23.3333H29.4192C28.045 27.2142 24.3525 30 20 30C14.4775 30 10 25.5225 10 20C10 14.4775 14.4775 9.99999 20 9.99999C22.5492 9.99999 24.8683 10.9617 26.6342 12.5325L31.3483 7.81833C28.3717 5.04416 24.39 3.33333 20 3.33333C10.7958 3.33333 3.33335 10.7958 3.33335 20C3.33335 29.2042 10.7958 36.6667 20 36.6667C29.2042 36.6667 36.6667 29.2042 36.6667 20C36.6667 18.8825 36.5517 17.7917 36.3425 16.7358Z"
                            fill="#FFC107" />
                        <path
                            d="M5.25497 12.2425L10.7308 16.2583C12.2125 12.59 15.8008 9.99999 20 9.99999C22.5491 9.99999 24.8683 10.9617 26.6341 12.5325L31.3483 7.81833C28.3716 5.04416 24.39 3.33333 20 3.33333C13.5983 3.33333 8.04663 6.94749 5.25497 12.2425Z"
                            fill="#FF3D00" />
                        <path
                            d="M20 36.6667C24.305 36.6667 28.2167 35.0192 31.1742 32.34L26.0159 27.975C24.3425 29.2425 22.2625 30 20 30C15.665 30 11.9842 27.2359 10.5975 23.3784L5.16254 27.5659C7.92087 32.9634 13.5225 36.6667 20 36.6667Z"
                            fill="#4CAF50" />
                        <path
                            d="M36.3425 16.7358H35V16.6667H20V23.3333H29.4192C28.7592 25.1975 27.56 26.805 26.0133 27.9758C26.0142 27.975 26.015 27.975 26.0158 27.9742L31.1742 32.3392C30.8092 32.6708 36.6667 28.3333 36.6667 20C36.6667 18.8825 36.5517 17.7917 36.3425 16.7358Z"
                            fill="#1976D2" />
                    </svg>
                </div>

                <span class="w-5/6 px-4 py-3 font-bold text-center">Sign in with Google</span>
            </a>

            <div class="flex items-center justify-between mt-4">
                <span class="w-1/5 border-b dark:border-gray-600 lg:w-1/4"></span>

                <a href="#" class="text-xs text-center text-gray-500 uppercase dark:text-gray-400 hover:underline">o conectate usando email</a>

                <span class="w-1/5 border-b dark:border-gray-400 lg:w-1/4"></span>
            </div>
			<?php 
			echo "<form action=\"$me\" method=\"get\" >"; 
			echo "<input type=\"hidden\" name=\"fas\" value=\"$fas\">";
			echo "<input type=\"hidden\" name=\"iv\" value=\"$iv\">";
			?>

			
			

            <div class="mt-4">
                <label class="block mb-2 text-sm font-medium text-gray-600 dark:text-gray-200"
                    for="LoggingEmailAddress">Nombre</label>
				<?php 
				echo "<input type=\"text\" name=\"fullname\" value=\"$fullname\"";
				?>
                    class="block w-full px-4 py-2 text-gray-700 bg-white border border-gray-300 rounded-md dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 focus:border-blue-500 dark:focus:border-blue-500 focus:outline-none focus:ring">
            </div>

            <div class="mt-4">
                <div class="flex justify-between">
                    <label class="block mb-2 text-sm font-medium text-gray-600 dark:text-gray-200"
                        for="loggingPassword">Correo electrónico</label>
                </div>
				<?php 
				echo "<input type=\"email\" name=\"email\" value=\"$email\"";
				?>
                    class="block w-full px-4 py-2 text-gray-700 bg-white border border-gray-300 rounded-md dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 focus:border-blue-500 dark:focus:border-blue-500 focus:outline-none focus:ring"
                    >
            </div>

            <div class="mt-8">
                <input type="submit" 
                    class="w-full px-4 py-2 tracking-wide text-white transition-colors duration-200 transform bg-gray-700 rounded hover:bg-gray-600 focus:outline-none focus:bg-gray-600"
					value="Aceptar términos y servicios">
				</input>
            </div>
</form>
            <div class="flex items-center justify-between mt-4">
                <span class="w-1/5 border-b dark:border-gray-600 md:w-1/4"></span>

                <a href="#" class="text-xs text-gray-500 uppercase dark:text-gray-400 hover:underline">Términos y servicios</a>

                <span class="w-1/5 border-b dark:border-gray-600 md:w-1/4"></span>
            </div>
        </div>
    </div>
</body>

</html>
		<?php
/*
		if (! isset($_GET['fas']))  {
			echo "<br><b style=\"color:red;\">ERROR! Incomplete data passed from NDS</b>\n";
		} else {
			echo "
				<form action=\"$me\" method=\"get\" >
					<input type=\"hidden\" name=\"fas\" value=\"$fas\">
					<input type=\"hidden\" name=\"iv\" value=\"$iv\">
					<hr>Full Name:<br>
					<input type=\"text\" name=\"fullname\" value=\"$fullname\">
					<br>
					Email Address:<br>
					<input type=\"email\" name=\"email\" value=\"$email\">
					<br><br>
					<input type=\"submit\" value=\"Accept Terms of Service\">
				</form>
				<hr>
			";

			flush();
		}
*/

	} else {
		thankyou_page();
	}
}

function status_page() {
	$me=$_SERVER['SCRIPT_NAME'];
	$clientip=$GLOBALS["clientip"];
	$clientmac=$GLOBALS["clientmac"];
	$gatewayname=$GLOBALS["gatewayname"];
	$gatewayaddress=$GLOBALS["gatewayaddress"];
	$gatewaymac=$GLOBALS["gatewaymac"];
	$clientif=$GLOBALS["clientif"];
	$originurl=$GLOBALS["originurl"];
	$redir=rawurldecode($originurl);

	// Is the client already logged in?
	if ($_GET["status"] == "authenticated") {
		echo "
			<p><big-red>You are already logged in and have access to the Internet.</big-red></p>
			<hr>
			<p><italic-black>You can use your Browser, Email and other network Apps as you normally would.</italic-black></p>
		";

		read_terms();

		echo "
			<p>
			Your device originally requested <b>$redir</b>
			<br>
			Click or tap Continue to go to there.
			</p>
			<form>
				<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='".$redir."'\" >
			</form>
		";
	} else {
		echo "
			<p><big-red>ERROR 404 - Page Not Found.</big-red></p>
			<hr>
			<p><italic-black>The requested resource could not be found.</italic-black></p>
		";
	}
	flush();
}

function landing_page() {
	$me=$_SERVER['SCRIPT_NAME'];
	$fas=$_GET["fas"];
	$iv=$GLOBALS["iv"];
	$originurl=$GLOBALS["originurl"];
	$gatewayaddress=$GLOBALS["gatewayaddress"];
	$gatewayname=$GLOBALS["gatewayname"];
	$clientif=$GLOBALS["clientif"];
	$client_zone=$GLOBALS["client_zone"];
	$fullname=$_GET["fullname"];
	$email=$_GET["email"];
	$redir=rawurldecode($originurl);

	echo "
		<p>
			<big-red>
				You are now logged in and have been granted access to the Internet.
			</big-red>
		</p>
		<hr>
		<med-blue>You are connected to $client_zone</med-blue><br>
		<p>
			<italic-black>
				You can use your Browser, Email and other network Apps as you normally would.
			</italic-black>
		</p>
		<p>
		Your device originally requested <b>$redir</b>
		<br>
		Click or tap Continue to go to there.
		</p>
		<form>
			<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='".$redir."'\" >
		</form>
		<hr>
	";

	read_terms();
	flush();
}

function splash_header() {
	$imagepath=$GLOBALS["imagepath"];
	$gatewayname=$GLOBALS["gatewayname"];
	$gatewayname=htmlentities(rawurldecode($gatewayname), ENT_HTML5, "UTF-8", FALSE);

	// Add headers to stop browsers from cacheing 
	header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
	header("Cache-Control: no-cache");
	header("Pragma: no-cache");

	// Output the common header html
	echo "<!DOCTYPE html>\n<html>\n<head>
		<meta charset=\"utf-8\" />
		<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
		<link rel=\"shortcut icon\" href=$imagepath type=\"image/x-icon\">
		<title>$gatewayname</title>
		<style>
	";
	flush();
	//insert_css();
	flush();
	echo "
		</style>
		</head>
		<body>
		<div class=\"offset\">
		<med-blue>
			$gatewayname
		</med-blue><br>
		<div class=\"insert\">
	";
	flush();
}

function footer() {
	$imagepath=$GLOBALS["imagepath"];
	$version=$GLOBALS["version"];
	$year=date("Y");
	echo "
		<hr>
		<div style=\"font-size:0.5em;\">
			<img style=\"height:60px; width:60px; float:left;\" src=\"$imagepath\" alt=\"Splash Page: For access to the Internet.\">
			&copy; The openNDS Project 2015 - $year<br>
			openNDS $version
			<br><br><br><br>
		</div>
		</div>
		</div>
		</body>
		</html>
	";
	exit(0);
}

function read_terms() {
	#terms of service button
	$me=$_SERVER['SCRIPT_NAME'];
	$fas=$GLOBALS["fas"];
	$iv=$GLOBALS["iv"];

	echo "
		<form action=\"$me\" method=\"get\">
			<input type=\"hidden\" name=\"fas\" value=\"$fas\">
			<input type=\"hidden\" name=\"iv\" value=\"$iv\">
			<input type=\"hidden\" name=\"terms\" value=\"yes\">
			<input type=\"submit\" value=\"Read Terms of Service\" >
		</form>
	";
}

function display_terms () {
	# This is the all important "Terms of service"
	# Edit this long winded generic version to suit your requirements.
	####
	# WARNING #
	# It is your responsibility to ensure these "Terms of Service" are compliant with the REGULATIONS and LAWS of your Country or State.
	# In most locations, a Privacy Statement is an essential part of the Terms of Service.
	####

	#Privacy
	echo "
		<b style=\"color:red;\">Privacy.</b><br>
		<b>
			By logging in to the system, you grant your permission for this system to store any data you provide for
			the purposes of logging in, along with the networking parameters of your device that the system requires to function.<br>
			All information is stored for your convenience and for the protection of both yourself and us.<br>
			All information collected by this system is stored in a secure manner and is not accessible by third parties.<br>
			In return, we grant you FREE Internet access.
		</b><hr>
	";
	flush();

	# Terms of Service
	echo "
		<b style=\"color:red;\">Terms of Service for this Hotspot.</b> <br>

		<b>Access is granted on a basis of trust that you will NOT misuse or abuse that access in any way.</b><hr>

		<b>Please scroll down to read the Terms of Service in full or click the Continue button to return to the Acceptance Page</b>

		<form>
			<input type=\"button\" VALUE=\"Continue\" onClick=\"history.go(-1);return true;\">
		</form>
	";
	flush();

	# Proper Use
	echo "
		<hr>
		<b>Proper Use</b>

		<p>
			This Hotspot provides a wireless network that allows you to connect to the Internet. <br>
			<b>Use of this Internet connection is provided in return for your FULL acceptance of these Terms Of Service.</b>
		</p>

		<p>
			<b>You agree</b> that you are responsible for providing security measures that are suited for your intended use of the Service.
			For example, you shall take full responsibility for taking adequate measures to safeguard your data from loss.
		</p>

		<p>
			While the Hotspot uses commercially reasonable efforts to provide a secure service,
			the effectiveness of those efforts cannot be guaranteed.
		</p>

		<p>
			<b>You may</b> use the technology provided to you by this Hotspot for the sole purpose
			of using the Service as described here.
			You must immediately notify the Owner of any unauthorized use of the Service or any other security breach.<br><br>
			We will give you an IP address each time you access the Hotspot, and it may change.
			<br>
			<b>You shall not</b> program any other IP or MAC address into your device that accesses the Hotspot.
			You may not use the Service for any other reason, including reselling any aspect of the Service.
			Other examples of improper activities include, without limitation:
		</p>

			<ol>
				<li>
					downloading or uploading such large volumes of data that the performance of the Service becomes
					noticeably degraded for other users for a significant period;
				</li>

				<li>
					attempting to break security, access, tamper with or use any unauthorized areas of the Service;
				</li>

				<li>
					removing any copyright, trademark or other proprietary rights notices contained in or on the Service;
				</li>

				<li>
					attempting to collect or maintain any information about other users of the Service
					(including usernames and/or email addresses) or other third parties for unauthorized purposes;
				</li>

				<li>
					logging onto the Service under false or fraudulent pretenses;
				</li>

				<li>
					creating or transmitting unwanted electronic communications such as SPAM or chain letters to other users
					or otherwise interfering with other user's enjoyment of the service;
				</li>

				<li>
					transmitting any viruses, worms, defects, Trojan Horses or other items of a destructive nature; or
				</li>

				<li>
					using the Service for any unlawful, harassing, abusive, criminal or fraudulent purpose.
				</li>
			</ol>
	";
	flush();

	# Content Disclaimer
	echo "
		<hr>
		<b>Content Disclaimer</b>

		<p>
			The Hotspot Owners do not control and are not responsible for data, content, services, or products
			that are accessed or downloaded through the Service.
			The Owners may, but are not obliged to, block data transmissions to protect the Owner and the Public.
		</p>

		The Owners, their suppliers and their licensors expressly disclaim to the fullest extent permitted by law,
		all express, implied, and statutary warranties, including, without limitation, the warranties of merchantability
		or fitness for a particular purpose.
		<br><br>
		The Owners, their suppliers and their licensors expressly disclaim to the fullest extent permitted by law
		any liability for infringement of proprietory rights and/or infringement of Copyright by any user of the system.
		Login details and device identities may be stored and be used as evidence in a Court of Law against such users.
		<br>
	";
	flush();

	# Limitation of Liability
	echo "

		<hr><b>Limitation of Liability</b>

		<p>
			Under no circumstances shall the Owners, their suppliers or their licensors be liable to any user or
			any third party on account of that party's use or misuse of or reliance on the Service.
		</p>

		<hr><b>Changes to Terms of Service and Termination</b>

		<p>
			We may modify or terminate the Service and these Terms of Service and any accompanying policies,
			for any reason, and without notice, including the right to terminate with or without notice,
			without liability to you, any user or any third party. Please review these Terms of Service
			from time to time so that you will be apprised of any changes.
		</p>

		<p>
			We reserve the right to terminate your use of the Service, for any reason, and without notice.
			Upon any such termination, any and all rights granted to you by this Hotspot Owner shall terminate.
		</p>
	";
	flush();

	# Inemnity
	echo "
		<hr><b>Indemnity</b>

		<p>
			<b>You agree</b> to hold harmless and indemnify the Owners of this Hotspot,
			their suppliers and licensors from and against any third party claim arising from
			or in any way related to your use of the Service, including any liability or expense arising from all claims,
			losses, damages (actual and consequential), suits, judgments, litigation costs and legal fees, of every kind and nature.
		</p>

		<hr>
		<form>
			<input type=\"button\" VALUE=\"Continue\" onClick=\"history.go(-1);return true;\">
		</form>
	";
	flush();
}

function insert_css() {
	echo "
	body {
		background-color: lightgrey;
		color: black;
		margin-left: 5%;
		margin-right: 5%;
		text-align: left;
	}

	hr {
		display:block;
		margin-top:0.5em;
		margin-bottom:0.5em;
		margin-left:auto;
		margin-right:auto;
		border-style:inset;
		border-width:5px;
	} 

	.offset {
		background: rgba(300, 300, 300, 0.6);
		margin-left:auto;
		margin-right:auto;
		max-width:600px;
		min-width:200px;
		padding: 5px;
	}

	.insert {
		background: rgba(350, 350, 350, 0.7);
		border: 2px solid #aaa;
		border-radius: 4px;
		min-width:200px;
		max-width:100%;
		padding: 5px;
	}

	img {
		width: 40%;
		max-width: 180px;
		margin-left: 0%;
		margin-right: 5%;
	}

	input[type=text], input[type=email], input[type=password] {
		font-size: 1em;
		line-height: 2.0em;
		height: 2.0em;
		width: 14.0em;
		color: black;
		background: lightgrey;
	}

	input[type=submit], input[type=button] {
		font-size: 1em;
		line-height: 2.0em;
		height: 2.0em;
		width: 14.0em;
		color: black;
		font-weight: bold;
		background: lightblue;
	}

	med-blue {
		font-size: 1.2em;
		color: blue;
		font-weight: bold;
		font-style: normal;
	}

	big-red {
		font-size: 1.5em;
		color: red;
		font-weight: bold;
	}

	italic-black {
		font-size: 1.0em;
		color: black;
		font-weight: bold;
		font-style: italic;
	}

	copy-right {
		font-size: 0.7em;
		color: darkgrey;
		font-weight: bold;
		font-style:italic;
	}

	";
	flush();
}

?>
