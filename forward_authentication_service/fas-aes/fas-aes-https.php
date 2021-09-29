<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/* $roots_includes = array(
	'/functions/body-class.php',
	'/functions/connections.php'
  );
  
  foreach($roots_includes as $file){
	if(!$filepath = locate_template($file)) {
	  trigger_error("Error locating `$file` for inclusion!", E_USER_ERROR);
	}
  
	require_once $filepath;
  }
  unset($file, $filepath); */

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
if (ob_get_level()) {
	ob_end_clean();
}

//force redirect to secure page
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] == "off") {
	$redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
	header('HTTP/1.1 301 Moved Permanently');
	header('Location: ' . $redirect);
	exit();
}

// setup some defaults
date_default_timezone_set("UTC");
$client_zone = $fullname = $email = $invalid = "";
$cipher = "AES-256-CBC";
$me = $_SERVER['SCRIPT_NAME'];

if (file_exists("/etc/config/opennds")) {
	$logpath = "/tmp/";
} elseif (file_exists("/etc/opennds/opennds.conf")) {
	$logpath = "/run/";
} else {
	$logpath = "";
}

###############################################################################
#
# Set the pre-shared key. This MUST be the same as faskey in the openNDS config
#
$key = "1234567890";
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
$sessionlength = 0; // minutes (1440 minutes = 24 hours)
$uploadrate = 0; // kbits/sec (500 kilobits/sec = 0.5 Megabits/sec)
$downloadrate = 0; // kbits/sec (1000 kilobits/sec = 1.0 Megabits/sec)
$uploadquota = 0; // kBytes (500000 kiloBytes = 500 MegaBytes)
$downloadquota = 0; // kBytes (1000000 kiloBytes = 1 GigaByte)

#############################################################################################################
#
# Custom string to be sent to Binauth
#
# Define a custom string that will be sent to BunAuth for additional local post authentication processing.
# Binauth is most useful for writing a local log on the openNDS router
$custom = "Optional Custom data for BinAuth";

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

	$acklist = base64_decode($_POST["payload"]);

	if (isset($_POST["gatewayhash"])) {
		$gatewayhash = $_POST["gatewayhash"];
	} else {
		# invalid call, so:
		exit(0);
	}

	if (!file_exists("$logpath" . "$gatewayhash")) {
		# no clients waiting, so:
		exit(0);
	}

	if ($_POST["auth_get"] == "clear") {
		$auth_list = scandir("$logpath" . "$gatewayhash");
		array_shift($auth_list);
		array_shift($auth_list);

		foreach ($auth_list as $client) {
			unlink("$logpath" . "$gatewayhash/$client");
		}
		# Stale entries cleared, so:
		exit(0);
	}

	# Set default empty authlist:
	$authlist = "*";

	if ($_POST["auth_get"] == "list") {
		$auth_list = scandir("$logpath" . "$gatewayhash");
		array_shift($auth_list);
		array_shift($auth_list);

		foreach ($auth_list as $client) {
			$clientauth = file("$logpath" . "$gatewayhash/$client");
			$authlist = $authlist . " " . rawurlencode(trim($clientauth[0]));
			unlink("$logpath" . "$gatewayhash/$client");
		}
		echo trim("$authlist");
	} else if ($_POST["auth_get"] == "view") {

		if ($acklist != "none") {
			$acklist_r = explode("\n", $acklist);

			foreach ($acklist_r as $client) {
				$client = ltrim($client, "* ");

				if ($client != "") {
					if (file_exists("$logpath" . "$gatewayhash/$client")) {
						unlink("$logpath" . "$gatewayhash/$client");
					}
				}
			}
			echo "ack";
		} else {
			$auth_list = scandir("$logpath" . "$gatewayhash");
			array_shift($auth_list);
			array_shift($auth_list);

			foreach ($auth_list as $client) {
				$clientauth = file("$logpath" . "$gatewayhash/$client");
				$authlist = $authlist . " " . rawurlencode(trim($clientauth[0]));
			}
			echo trim("$authlist");
		}
	}
	exit(0);
}
#############################################################################################################

// Service requests for remote image
if (isset($_GET["get_image"])) {
	$url = $_GET["get_image"];
	$imagetype = $_GET["imagetype"];
	get_image($url, $imagetype);
	exit(0);
}

// define the image to display
// eg. https://avatars1.githubusercontent.com/u/62547912 is the openNDS Portal Lens Flare
$imageurl = "https://avatars1.githubusercontent.com/u/62547912";
$imagetype = "png";
$scriptname = basename($_SERVER['SCRIPT_NAME']);
$imagepath = htmlentities("$scriptname?get_image=$imageurl&imagetype=$imagetype");

// Get the query string components
if (isset($_GET['status'])) {
	$redir = $_GET['redir'];
	$redir_r = explode("fas=", $redir);
	$fas = $redir_r[1];
	$iv = $_GET['iv'];
} else if (isset($_GET['fas'])) {
	$fas = $_GET['fas'];
	$iv = $_GET['iv'];
} elseif (isset($_GET['frommail'])) {
	# code...
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

$ndsparamlist = explode(" ", "clientip clientmac gatewayname version hid gatewayaddress gatewaymac authdir originurl clientif admin_email location");

if (isset($_GET['fas']) and isset($_GET['iv'])) {
	$string = $_GET['fas'];
	$iv = $_GET['iv'];
	$decrypted = openssl_decrypt(base64_decode($string), $cipher, $key, 0, $iv);
	$dec_r = explode(", ", $decrypted);

	foreach ($ndsparamlist as $ndsparm) {
		foreach ($dec_r as $dec) {
			@list($name, $value) = explode("=", $dec);
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
$client_zone_r = explode(" ", trim($clientif));

if (!isset($client_zone_r[1])) {
	$client_zone = "zona local:" . $client_zone_r[0];
} else {
	$client_zone = "zona global:" . str_replace(":", "", $client_zone_r[1]);
}

#################################################################################
# Create auth list directory for this gateway
# This list will be sent to NDS when it requests it.
#################################################################################

$gwname = hash('sha256', trim($gatewayname));

if (!file_exists("$logpath" . "$gwname")) {
	mkdir("$logpath" . "$gwname", 0700);
}

#######################################################
//Start Outputting the requested responsive page:
#######################################################

//splash_header();

if (isset($_GET["terms"])) {
	// ToS requested
	display_terms();
} elseif (isset($_GET["status"])) {
	// The status page is triggered by a client if already authenticated by openNDS (eg by clicking "back" on their browser)
	status_page();
} elseif (isset($_GET["auth"])) {
	# Verification is complete so now wait for openNDS to authenticate the client.
	authenticate_page();
} elseif (isset($_GET["landing"])) {
	// The landing page is served to the client immediately after openNDS authentication, but many CPDs will immediately close
	landing_page();
} else {
	login_page();
}

#############################################################################################################
// Functions:

function get_image($url, $imagetype)
{
	header("Content-type: image/$imagetype");
	readfile($url);
}

function authenticate_page()
{
	# Display a "logged in" landing page once NDS has authenticated the client.
	# or a timed out error if we do not get authenticated by NDS
	$me = $_SERVER['SCRIPT_NAME'];
	$host = $_SERVER['HTTP_HOST'];
	$clientip = $GLOBALS["clientip"];
	$gatewayname = $GLOBALS["gatewayname"];
	$gatewayaddress = $GLOBALS["gatewayaddress"];
	$gatewaymac = $GLOBALS["gatewaymac"];
	$hid = $GLOBALS["hid"];
	$key = $GLOBALS["key"];
	$clientif = $GLOBALS["clientif"];
	$originurl = $GLOBALS["originurl"];
	$redir = rawurldecode($originurl);
	$sessionlength = $GLOBALS["sessionlength"];
	$uploadrate = $GLOBALS["uploadrate"];
	$downloadrate = $GLOBALS["downloadrate"];
	$uploadquota = $GLOBALS["uploadquota"];
	$downloadquota = $GLOBALS["downloadquota"];
	$gwname = $GLOBALS["gwname"];
	$logpath = $GLOBALS["logpath"];
	$custom = $GLOBALS["custom"];

	$rhid = hash('sha256', trim($hid) . trim($key));

	# Construct the client authentication string or "log"
	# Note: override values set earlier if required, for example by testing clientif 
	$log = "$rhid $sessionlength $uploadrate $downloadrate $uploadquota $downloadquota " . rawurlencode($custom) . "\n";

	$logfile = "$logpath" . "$gwname/$rhid";

	if (!file_exists($logfile)) {
		file_put_contents("$logfile", "$log");
	}

	flush();
	$count = 0;
	$maxcount = 5;


	loading_page();

	for ($i = 1; $i <= $maxcount; $i++) {

		sleep(1);

		if (file_exists("$logfile")) {
			$authed = "no";
		} else {
			//no list so must be authed
			$authed = "yes";
			write_log();
		}

		//if ($authed == "yes") {
		if ("yes" == "yes") {
			//echo "<br><b>Authenticated</b><br>";
			landing_page();
			flush();
			break;
		}
	}

	if ($i > $maxcount) {
		flush();
		unlink("$logfile");

?>
		<!DOCTYPE html>
		<html>

		<head>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
			<title>Timeout</title>
			<meta name="viewport" content="width=device-width, initial-scale=1">

		</head>

		<body>
			<style>
				.aesconder {
					visibility: hidden;
				}
			</style>
			<div class="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
				<div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center">
					<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true"></div>
					<span class="hidden inline-block align-middle h-screen" aria-hidden="true">​</span>
					<div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all my-8 align-middle max-w-lg w-full">
						<div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
							<div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:h-16 sm:w-16">
								<svg class="h-12 w-12 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
								</svg>
							</div>
							<div class="mt-3 text-center sm:mt-0">
								<h3 class="text-2xl leading-6 font-medium text-gray-900 pt-3" id="modal-title">
									El Portal ha expirado
								</h3>
								<div class="mt-2">
									<p class="text-sm text-gray-500">
										Es posible que tenga que apagar y encender su WiFi para volver a conectarse.
										<br>
										Pulse continuar para volver a cargar.
									</p>
								</div>
							</div>
						</div>
						<div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
							<button type="button" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-500 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:ml-3 sm:w-auto sm:text-sm">
								Continuar
							</button>
							<!--<button type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">
								Cancelar
							</button>-->
						</div>
					</div>
				</div>
			</div>


		</body>

		</html>
	<?php
	}
}

function loading_page()
{
	?>

	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<!--<link href="../pages/tailwind.css" rel="stylesheet">-->

	</head>

	<body>
		<div wire:loading class="aesconder fixed top-0 left-0 right-0 bottom-0 w-full h-screen z-50 overflow-hidden bg-gray-700 opacity-75 flex flex-col items-center justify-center">
			<div class="loader ease-linear rounded-full border-4 border-t-4 border-gray-200 h-12 w-12 mb-4"></div>
			<h2 class="text-center text-white text-xl font-semibold">Conectando...</h2>
			<p class="w-1/3 text-center text-white">Conectando con el servidor, por favor no cierres la página.</p>
		</div>
	</body>

	<style>
		<?php
		echo file_get_contents('../pages/tailwind.css'); //añadimos el css directamente sobre el DOM
		?>.loader {
			border-top-color: #3498db;
			-webkit-animation: spinner 1.5s linear infinite;
			animation: spinner 1.5s linear infinite;
		}

		@-webkit-keyframes spinner {
			0% {
				-webkit-transform: rotate(0deg);
			}

			100% {
				-webkit-transform: rotate(360deg);
			}
		}

		@keyframes spinner {
			0% {
				transform: rotate(0deg);
			}

			100% {
				transform: rotate(360deg);
			}
		}
	</style>


<?php
	flush();
}

function thankyou_page()
{
	# Output the "Thankyou page" with a continue button
	# You could include information or advertising on this page
	# Be aware that many devices will close the login browser as soon as
	# the client taps continue, so now is the time to deliver your message.

	# You can also send a custom data string to BinAuth. Set the variable $custom to the desired value
	# Max length 256 characters
	$custom = "Custom data sent to BinAuth";
	$custom = base64_encode($custom);

	$me = $_SERVER['SCRIPT_NAME'];
	$host = $_SERVER['HTTP_HOST'];
	$fas = $GLOBALS["fas"];
	$iv = $GLOBALS["iv"];
	$clientip = $GLOBALS["clientip"];
	$gatewayname = $GLOBALS["gatewayname"];
	$gatewayaddress = $GLOBALS["gatewayaddress"];
	$gatewaymac = $GLOBALS["gatewaymac"];
	$key = $GLOBALS["key"];
	$hid = $GLOBALS["hid"];
	$clientif = $GLOBALS["clientif"];
	$originurl = $GLOBALS["originurl"];
	$fullname = $_GET["fullname"];
	$email = $_GET["email"];
	$codigo = $_GET["codigo"];
	$fullname_url = rawurlencode($fullname);
	$auth = "yes";

?>
	<!doctype html>
	<html>

	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<link href="../pages/tailwind.css" rel="stylesheet">
		<title>Login correcto</title>
	</head>

	<body>
		<div class="h-16"></div>
		<div class="flex max-w-sm mx-auto overflow-hidden bg-white rounded-lg shadow-lg dark:bg-gray-800 lg:max-w-4xl">
			<div class="hidden bg-cover lg:block lg:w-1/2" style="background-image:url('https://images.unsplash.com/photo-1606660265514-358ebbadc80d?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=1575&q=80')">
			</div>

			<div class="w-full px-6 py-8 md:px-8 lg:w-1/2">

				<?php
				$match = 0;
				if (isset($_GET["codigo"])) {
					try {
						// first connect to database with the PDO object. 
						$con = new \PDO("mysql:host=miregau123.mysql.db;dbname=miregau123;charset=utf8", "miregau123", "Putabbdd1", [
							PDO::ATTR_EMULATE_PREPARES => false,
							PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
						]);
					} catch (\PDOException $e) {
						// if connection fails, show PDO error. 
						echo "Error connecting to mysql: " . $e->getMessage();
					}

					$sentencia = $con->prepare("SELECT * FROM users WHERE email=? AND codigo=? ;");
					$sentencia->bindParam(1, $email);
					$sentencia->bindParam(2, $codigo);
					$sentencia->execute();
					/* obtener valor */
					$result = $sentencia->fetchAll();

					//print_r($result);
					echo $result[0]['codigo'];
					echo count($result);
					$match  = count($result);

					$intents = $result[0]['n_errores_codigo'] + 1;
					$sentencia = $con->prepare("UPDATE users SET n_errores_codigo = ? WHERE email=? AND codigo=? ;");
					$sentencia->bindParam(1, $intents);
					$sentencia->bindParam(2, $email);
					$sentencia->bindParam(3, $codigo);
				}

				echo "asd\n";

				if ($match != 1) {
					# Falta introducir codigo
					echo "falta codigo";


				?>

					<h2 class="text-2xl font-semibold text-center text-gray-700 dark:text-white">Código de verificación</h2>
					<p class="text-xl text-center text-gray-600 dark:text-gray-200">Hemos enviado un código de verificación a tu correo, introducelo a continuación.</p>
					<div class="flex justify-center">
						<svg class="text-gray-600 h-20 w-20" xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width={2} d="M3 19v-8.93a2 2 0 01.89-1.664l7-4.666a2 2 0 012.22 0l7 4.666A2 2 0 0121 10.07V19M3 19a2 2 0 002 2h14a2 2 0 002-2M3 19l6.75-4.5M21 19l-6.75-4.5M3 10l6.75 4.5M21 10l-6.75 4.5m0 0l-1.14.76a2 2 0 01-2.22 0l-1.14-.76" />
						</svg>
					</div>

					<?php
					echo "<form action=\"$me\" method=\"get\">";
					echo "<input type=\"hidden\" name=\"fas\" value=\"$fas\">";
					echo "<input type=\"hidden\" name=\"iv\" value=\"$iv\">";
					echo "<input type=\"hidden\" name=\"fullname\" value=\"$fullname_url\">";
					echo "<input type=\"hidden\" name=\"email\" value=\"$email\">";

					?>
					<div class="text-gray-700">
						<label class="block mb-1" for="forms-helpTextCode">Código</label>
						<input name="codigo" class="w-full h-10 px-3 text-base placeholder-gray-600 border rounded-lg focus:shadow-outline" type="password" id="forms-helpTextCode" aria-describedby="passwordHelp" />
						<span class="text-xs text-gray-600" id="passwordHelp">Tu código debe contener 6 caracteres.</span>
					</div>

					<div class="mt-8 justify-items-end">
						<input type="submit" class="w-full px-4 py-2 tracking-wide text-white transition-colors duration-200 transform bg-gray-700 rounded hover:bg-gray-600 focus:outline-none focus:bg-gray-600" value="Log in">
						</input>
					</div>
					</form>
				<?php
				} else {
					echo "codigo correcto";
					# Hemos introducido bien el código de 6 dígitos

					try {
						// first connect to database with the PDO object. 
						$con = new \PDO("mysql:host=miregau123.mysql.db;dbname=miregau123;charset=utf8", "miregau123", "Putabbdd1", [
							PDO::ATTR_EMULATE_PREPARES => false,
							PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
						]);
					} catch (\PDOException $e) {
						// if connection fails, show PDO error. 
						echo "Error connecting to mysql: " . $e->getMessage();
					}
					$zero = 0;
					$zero2 = 0;
					$active = 1;
					$sentencia = $con->prepare("UPDATE users SET codigo = ?, active = ?, n_errores_codigo = ? WHERE email = ? ;");
					$sentencia->bindParam(1, $zero2);
					$sentencia->bindParam(2, $active);
					$sentencia->bindParam(3, $zero);
					$sentencia->bindParam(4, $email);
					$sentencia->execute();

				?>
					<div>
						<svg class="text-green-600" xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
							<path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
						</svg>
					</div>


					<h2 class="text-2xl font-semibold text-center text-gray-700 dark:text-white">WSECURITY</h2>

					<p class="text-xl text-center text-gray-600 dark:text-gray-200">Login correcto</p>


					<?php





					echo "<form action=\"$me\" method=\"get\">";
					echo "<input type=\"hidden\" name=\"fas\" value=\"$fas\">";
					echo "<input type=\"hidden\" name=\"iv\" value=\"$iv\">";
					echo "<input type=\"hidden\" name=\"auth\" value=\"$auth\">";
					echo "<input type=\"hidden\" name=\"fullname\" value=\"$fullname_url\">";
					echo "<input type=\"hidden\" name=\"email\" value=\"$email\">";

					?>

					<div class="mt-8">
						<input type="submit" class="w-full px-4 py-2 tracking-wide text-white transition-colors duration-200 transform bg-gray-700 rounded hover:bg-gray-600 focus:outline-none focus:bg-gray-600" value="Conectar">
						</input>
					</div>
					</form>
				<?php
				flush();
				}
				?>
			</div>
		</div>
	</body>

	</html>


	<?php


	# TODO Aqui ejecutamos dos veces, hay que ejecutar esta parte solo si la variable codigo no esta en el GET
	# El login ha sido correcto, guardamos al usuario en la bbdd
	try {
		// first connect to database with the PDO object. 
		$con = new \PDO("mysql:host=miregau123.mysql.db;dbname=miregau123;charset=utf8", "miregau123", "Putabbdd1", [
			PDO::ATTR_EMULATE_PREPARES => false,
			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		]);
	} catch (\PDOException $e) {
		// if connection fails, show PDO error. 
		echo "Error connecting to mysql: " . $e->getMessage();
	}

	$sentencia = $con->prepare("SELECT * FROM users WHERE email=? ;");
	$sentencia->bindParam(1, $email);
	$sentencia->execute();
	/* obtener valor */
	$result = $sentencia->fetchAll();

	if (count($result) == 0) {

		$sentencia = $con->prepare("INSERT INTO users (username, email, codigo) VALUES (?, ?, ?)");
		$a = 0;
		$sentencia->bindParam(1, $fullname);
		$sentencia->bindParam(2, $email);
		$sentencia->bindParam(3, $a);

		$sentencia->execute();
	}

	/* 
CREATE TABLE `users` (
`email` VARCHAR( 100 ) NOT NULL PRIMARY KEY,
`username` VARCHAR( 32 ) NOT NULL ,
`codigo` VARCHAR( 32 ) NULL,
`active` INT( 1 ) NOT NULL DEFAULT '0',
`n_errores_codigo` INT(8) NOT NULL DEFAULT '0'
) ENGINE = MYISAM ; 
		*/
	if (!isset($_GET["codigo"])) {
		# creamos el usuario y su hash
		echo "asdfghjkl";
		$codigo = rand(100000, 999999);

		$sentencia = $con->prepare("UPDATE users SET codigo = ? WHERE email = ? ;");
		$sentencia->bindParam(1, $codigo);
		$sentencia->bindParam(2, $email);
		$sentencia->execute();

		// Enviamos codigo de verificación

		$to      = $email; // Send email to our user
		$subject = 'Signup | Verification'; // Give the email a subject 
		$message = 'Código de activación: ' . $codigo; // Our message above including the link

		$headers = 'From:noreply@miregalooriginal.com' . "\r\n"; // Set from headers

		if (mail($to, $subject, $message, $headers)) { // Send our email
			echo "enviado";
		} else {
			echo "no enviado";
		}

		flush();
	}
}

function write_log()
{
	# In this example we have decided to log all clients who are granted access
	# Note: the web server daemon must have read and write permissions to the folder defined in $logpath
	# By default $logpath is null so the logfile will be written to the folder this script resides in,
	# or the /tmp directory if on the NDS router

	if (file_exists("/etc/config/opennds")) {
		$logpath = "/tmp/";
	} elseif (file_exists("/etc/opennds/opennds.conf")) {
		$logpath = "/run/";
	} else {
		$logpath = "";
	}

	if (!file_exists("$logpath" . "ndslog")) {
		mkdir("$logpath" . "ndslog", 0700);
	}

	$me = $_SERVER['SCRIPT_NAME'];
	$script = basename($me, '.php');
	$host = $_SERVER['HTTP_HOST'];
	$user_agent = $_SERVER['HTTP_USER_AGENT'];
	$clientip = $GLOBALS["clientip"];
	$clientmac = $GLOBALS["clientmac"];
	$gatewayname = $GLOBALS["gatewayname"];
	$gatewayaddress = $GLOBALS["gatewayaddress"];
	$gatewaymac = $GLOBALS["gatewaymac"];
	$clientif = $GLOBALS["clientif"];
	$originurl = $GLOBALS["originurl"];
	$redir = rawurldecode($originurl);
	if (isset($_GET["fullname"])) {
		$fullname = $_GET["fullname"];
	} else {
		$fullname = "na";
	}

	if (isset($_GET["email"])) {
		$email = $_GET["email"];
	} else {
		$email = "na";
	}

	$log = date('Y-m-d H:i:s', $_SERVER['REQUEST_TIME']) .
		", $script, $gatewayname, $fullname, $email, $clientip, $clientmac, $clientif, $user_agent, $redir\n";

	if ($logpath == "") {
		$logfile = "ndslog/ndslog_log.php";

		if (!file_exists($logfile)) {
			@file_put_contents($logfile, "<?php exit(0); ?>\n");
		}
	} else {
		$logfile = "$logpath" . "ndslog/ndslog.log";
	}

	@file_put_contents($logfile, $log, FILE_APPEND);
}

function login_page()
{
	$fullname = $email = "";
	$me = $_SERVER['SCRIPT_NAME'];
	$fas = $_GET["fas"];
	$iv = $GLOBALS["iv"];
	$clientip = $GLOBALS["clientip"];
	$clientmac = $GLOBALS["clientmac"];
	$gatewayname = $GLOBALS["gatewayname"];
	$gatewayaddress = $GLOBALS["gatewayaddress"];
	$gatewaymac = $GLOBALS["gatewaymac"];
	$clientif = $GLOBALS["clientif"];
	$client_zone = $GLOBALS["client_zone"];
	$originurl = $GLOBALS["originurl"];

	if (isset($_GET["fullname"])) {
		$fullname = ucwords($_GET["fullname"]);
	}

	if (isset($_GET["email"])) {
		$email = $_GET["email"];
	}


	if (isset($_GET["acceptterms"])) {
		$acceptterms = $_GET["acceptterms"];
	}


	if ($fullname == "" or $email == "" or $acceptterms == "false") {
	?>
		<!doctype html>
		<html>

		<head>
			<meta charset="UTF-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1.0" />
			<link href="../pages/tailwind.css" rel="stylesheet">
			<title>Logging</title>
		</head>

		<body>
			<div class="h-16"></div>
			<div class="flex max-w-sm mx-auto overflow-hidden bg-white rounded-lg shadow-lg dark:bg-gray-800 lg:max-w-4xl">

				<!-- Lado izquierdo del cuadro -->
				<div class="hidden bg-cover lg:block lg:w-1/2" style="background-image:url('https://images.unsplash.com/photo-1606660265514-358ebbadc80d?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=1575&q=80')"></div>

				<!-- Lado derecho del cuadro -->
				<div class="w-full px-6 py-20 md:px-8 lg:w-1/2">
					<h2 class="text-2xl font-semibold text-center text-gray-700 dark:text-white">WSECURITY</h2>

					<p class="text-xl text-center text-gray-600 dark:text-gray-200">Estas conectado a
						<?php echo $client_zone; ?></p>

					<?php
					if (!isset($_GET['fas'])) {
					?>
						<p class="text-xl text-center text-red-600 dark:text-red-200">ERROR! Incomplete data passed from NDS</p>
					<?php
					}
					?>

					<a href="#" class="flex items-center justify-center mt-4 text-gray-600 rounded-lg shadow-md dark:bg-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600">
						<div class="px-4 py-3">
							<svg class="w-6 h-6" viewBox="0 0 40 40">
								<path d="M36.3425 16.7358H35V16.6667H20V23.3333H29.4192C28.045 27.2142 24.3525 30 20 30C14.4775 30 10 25.5225 10 20C10 14.4775 14.4775 9.99999 20 9.99999C22.5492 9.99999 24.8683 10.9617 26.6342 12.5325L31.3483 7.81833C28.3717 5.04416 24.39 3.33333 20 3.33333C10.7958 3.33333 3.33335 10.7958 3.33335 20C3.33335 29.2042 10.7958 36.6667 20 36.6667C29.2042 36.6667 36.6667 29.2042 36.6667 20C36.6667 18.8825 36.5517 17.7917 36.3425 16.7358Z" fill="#FFC107" />
								<path d="M5.25497 12.2425L10.7308 16.2583C12.2125 12.59 15.8008 9.99999 20 9.99999C22.5491 9.99999 24.8683 10.9617 26.6341 12.5325L31.3483 7.81833C28.3716 5.04416 24.39 3.33333 20 3.33333C13.5983 3.33333 8.04663 6.94749 5.25497 12.2425Z" fill="#FF3D00" />
								<path d="M20 36.6667C24.305 36.6667 28.2167 35.0192 31.1742 32.34L26.0159 27.975C24.3425 29.2425 22.2625 30 20 30C15.665 30 11.9842 27.2359 10.5975 23.3784L5.16254 27.5659C7.92087 32.9634 13.5225 36.6667 20 36.6667Z" fill="#4CAF50" />
								<path d="M36.3425 16.7358H35V16.6667H20V23.3333H29.4192C28.7592 25.1975 27.56 26.805 26.0133 27.9758C26.0142 27.975 26.015 27.975 26.0158 27.9742L31.1742 32.3392C30.8092 32.6708 36.6667 28.3333 36.6667 20C36.6667 18.8825 36.5517 17.7917 36.3425 16.7358Z" fill="#1976D2" />
							</svg>
						</div>

						<span class="w-5/6 px-4 py-3 font-bold text-center">Sign in with Google</span>
					</a>








					<div class="flex items-center justify-between mt-4">
						<span class="w-1/5 border-b dark:border-gray-600 lg:w-1/4"></span>

						<span class="text-xs text-center text-gray-500 uppercase dark:text-gray-400">o
							conectate usando email</span>

						<span class="w-1/5 border-b dark:border-gray-400 lg:w-1/4"></span>
					</div>




					<?php
					echo "<form action=\"$me\" method=\"get\" >";
					echo "<input type=\"hidden\" name=\"fas\" value=\"$fas\">";
					echo "<input type=\"hidden\" name=\"iv\" value=\"$iv\">";
					?>

					<div class="flex flex-col">

						<div class="mt-8">
							<label class="block mb-2 text-sm font-medium text-gray-600 dark:text-gray-200" for="LoggingEmailAddress">Nombre</label>
							<?php
							echo "<input type=\"text\" name=\"fullname\" value=\"$fullname\" ";
							?>
							placeholder="John Doe" class="block w-full px-4 py-2 text-gray-700 bg-white
							border rounded-md dark:bg-gray-800
							dark:text-gray-300
							focus:outline-none focus:ring
							<?php
							if (isset($_GET["fullname"]) and empty($fullname)) {
								echo " border-red-300\"> "; //cambia el color del borde del imput en caso de que este incorrecto
							?>
								<span class="flex items-center font-medium tracking-wide text-red-500 text-xs mt-1 ml-1">
									Falta introducir nombre de usuario
								</span>
							<?php
							} else {
								echo " border-gray-300 dark:border-gray-600 focus:border-blue-500 dark:focus:border-blue-500 \"> ";
							}
							?>
						</div>

						<div class="mt-8">

							<label class="block mb-2 text-sm font-medium text-gray-600 dark:text-gray-200" for="loggingPassword">Correo electrónico</label>
							<?php
							echo "<input type=\"email\" name=\"email\" value=\"$email\" ";
							?>
							placeholder="john@ejemplo.com" class="block w-full px-4 py-2 text-gray-700 bg-white
							border rounded-md dark:bg-gray-800
							dark:text-gray-300 focus:outline-none focus:ring

							<?php
							if (isset($_GET["email"]) and empty($email)) {
								echo " border-red-300\"> "; //cambia el color del borde del imput en caso de que este incorrecto
							?>


								<span class="flex items-center font-medium tracking-wide text-red-500 text-xs mt-1 ml-1">
									Falta introducir correo electrónico
								</span>
							<?php
							} else {
								echo " border-gray-300 dark:border-gray-600 focus:border-blue-500 dark:focus:border-blue-500 \"> "; //mantiene el color actual
							}
							?>
						</div>

						<div class="mt-8">

							<label class="inline-flex items-center">
								<input type='hidden' name='acceptterms' value="false">
								<input type="checkbox" name="acceptterms" value="true" class="h-5 w-5">
								<span class="ml-2">Aceptar

									<?php
									$me = $_SERVER['SCRIPT_NAME'];
									$fas = $GLOBALS["fas"];
									$iv = $GLOBALS["iv"];
									echo "<a href=\"" . $me . "?fas=" . $fas . "&iv=" . $iv . "&terms=yes" . "\"  class=\"underline\">términos y condiciones</a>";
									?>
								</span>

							</label>
							<?php
							if ($acceptterms == "false") {
							?>
								<span class="flex items-center font-medium tracking-wide text-red-500 text-xs mt-1 ml-1">
									Es obligatorio aceptar los términos y condiciones
								</span>
							<?php
							}
							?>
						</div>


						<div class="mt-8 justify-items-end">
							<input type="submit" class="w-full px-4 py-2 tracking-wide text-white transition-colors duration-200 transform bg-gray-700 rounded hover:bg-gray-600 focus:outline-none focus:bg-gray-600" value="Log in">
							</input>
						</div>

					</div>

					</form>
				</div>
			</div>
		</body>

		</html>
	<?php

	} else {
		thankyou_page();
	}
}

function status_page()
{
	$me = $_SERVER['SCRIPT_NAME'];
	$clientip = $GLOBALS["clientip"];
	$clientmac = $GLOBALS["clientmac"];
	$gatewayname = $GLOBALS["gatewayname"];
	$gatewayaddress = $GLOBALS["gatewayaddress"];
	$gatewaymac = $GLOBALS["gatewaymac"];
	$clientif = $GLOBALS["clientif"];
	$originurl = $GLOBALS["originurl"];
	$redir = rawurldecode($originurl);

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
				<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='" . $redir . "'\" >
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

function landing_page()
{
	$me = $_SERVER['SCRIPT_NAME'];
	$fas = $_GET["fas"];
	$iv = $GLOBALS["iv"];
	$originurl = $GLOBALS["originurl"];
	$gatewayaddress = $GLOBALS["gatewayaddress"];
	$gatewayname = $GLOBALS["gatewayname"];
	$clientif = $GLOBALS["clientif"];
	$client_zone = $GLOBALS["client_zone"];
	$fullname = $_GET["fullname"];
	$email = $_GET["email"];
	$redir = rawurldecode($originurl);



	?>
	<!DOCTYPE html>
	<html>

	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<title>Acceso concedido</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">

	</head>

	<body>
		<style>
			.aesconder {
				visibility: hidden;
			}
		</style>
		<div class="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
			<div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center">
				<div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true"></div>
				<span class="hidden inline-block align-middle h-screen" aria-hidden="true">​</span>
				<div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all my-8 align-middle max-w-lg w-full">
					<div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
						<div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-green-100 sm:h-16 sm:w-16">
							<svg class="h-12 w-12 text-green-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
							</svg>
						</div>
						<div class="mt-3 text-center sm:mt-0">
							<h3 class="text-2xl leading-6 font-medium text-gray-900 pt-3" id="modal-title">
								Acceso a internet concedido
							</h3>
							<div class="mt-2">
								<p class="text-sm text-gray-500">
									Ya puedes utilizar la aplicaciones con acceso a internet de forma habitual. Presiona continuar para cerrar la página.
								</p>
							</div>
						</div>
					</div>
					<div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
						<form>
							<?php
							echo "<input type=\"button\" VALUE=\"Continuar\" onClick=\"location.href='" . $redir . "'\" ";
							?>
							class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-green-500 text-base font-medium text-white hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 sm:ml-3 sm:w-auto sm:text-sm">
						</form>
					</div>
				</div>
			</div>
		</div>


	</body>

	</html>
<?php
	/* echo "
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
			<input type=\"button\" VALUE=\"Continue\" onClick=\"location.href='" . $redir . "'\" >
		</form>
		<hr>
	"; */

	flush();
}

/* function splash_header()
{
	$imagepath = $GLOBALS["imagepath"];
	$gatewayname = $GLOBALS["gatewayname"];
	$gatewayname = htmlentities(rawurldecode($gatewayname), ENT_HTML5, "UTF-8", FALSE);

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
} */

/* function footer()
{
	$imagepath = $GLOBALS["imagepath"];
	$version = $GLOBALS["version"];
	$year = date("Y");
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
} */

/* function read_terms()
{
	#terms of service button
	$me = $_SERVER['SCRIPT_NAME'];
	$fas = $GLOBALS["fas"];
	$iv = $GLOBALS["iv"];

	echo "
		<form action=\"$me\" method=\"get\">
			<input type=\"hidden\" name=\"fas\" value=\"$fas\">
			<input type=\"hidden\" name=\"iv\" value=\"$iv\">
			<input type=\"hidden\" name=\"terms\" value=\"yes\">
			<input type=\"submit\" value=\"Read Terms of Service\" >
		</form>
	";
} */

function display_terms()
{
?>

	<!doctype html>
	<html>

	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<link href="../pages/tailwind.css" rel="stylesheet">
		<title>Terminos de servicio</title>
	</head>

	<body>
		<footer class="text-gray-600 body-font">
			<div class="container px-5 py-8 mx-auto flex items-center sm:flex-row flex-col">
				<a class="flex title-font font-medium items-center md:justify-start justify-center text-gray-900">
					<svg xmlns="http://www.w3.org/2000/svg" class="h-10 w-10" fill="none" viewBox="0 0 24 24" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
					</svg>
					<span class="ml-3 text-xl">Wsecurity</span>
				</a>
				<p class="text-sm text-gray-500 sm:ml-4 sm:pl-4 sm:border-l-2 sm:border-gray-200 sm:py-2 sm:mt-0 mt-4">© 2020 Wsecurity —
					<a href="mailto:wsecurity@wsecurity.com" class="text-gray-600 ml-1" rel="noopener noreferrer" target="_blank">wsecurity@wsecurity.com</a>
				</p>
				<!-- <span class="inline-flex sm:ml-auto sm:mt-0 mt-4 justify-center sm:justify-start">
					<a class="text-gray-500">
						<svg fill="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" class="w-5 h-5" viewBox="0 0 24 24">
							<path d="M18 2h-3a5 5 0 00-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 011-1h3z"></path>
						</svg>
					</a>
					<a class="ml-3 text-gray-500">
						<svg fill="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" class="w-5 h-5" viewBox="0 0 24 24">
							<path d="M23 3a10.9 10.9 0 01-3.14 1.53 4.48 4.48 0 00-7.86 3v1A10.66 10.66 0 013 4s-4 9 5 13a11.64 11.64 0 01-7 2c9 5 20 0 20-11.5a4.5 4.5 0 00-.08-.83A7.72 7.72 0 0023 3z"></path>
						</svg>
					</a>
					<a class="ml-3 text-gray-500">
						<svg fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" class="w-5 h-5" viewBox="0 0 24 24">
							<rect width="20" height="20" x="2" y="2" rx="5" ry="5"></rect>
							<path d="M16 11.37A4 4 0 1112.63 8 4 4 0 0116 11.37zm1.5-4.87h.01"></path>
						</svg>
					</a>
					<a class="ml-3 text-gray-500">
						<svg fill="currentColor" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="0" class="w-5 h-5" viewBox="0 0 24 24">
							<path stroke="none" d="M16 8a6 6 0 016 6v7h-4v-7a2 2 0 00-2-2 2 2 0 00-2 2v7h-4v-7a6 6 0 016-6zM2 9h4v12H2z"></path>
							<circle cx="4" cy="4" r="2" stroke="none"></circle>
						</svg>
					</a>
				</span> -->
			</div>
		</footer>
	</body>

<?php
}


# Verificación de que están entrando con el enlace del email
if (isset($_GET['frommail']) && isset($_GET['email']) && !empty($_GET['email']) and isset($_GET['hash']) && !empty($_GET['hash'])) {


	try {
		// first connect to database with the PDO object. 
		$con = new \PDO("mysql:host=miregau123.mysql.db;dbname=miregau123;charset=utf8", "miregau123", "Putabbdd1", [
			PDO::ATTR_EMULATE_PREPARES => false,
			PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
		]);
	} catch (\PDOException $e) {
		// if connection fails, show PDO error. 
		echo "Error connecting to mysql: " . $e->getMessage();
	}

	echo "aiuwpbvpiWRUBVÑwrbv";

	$con = new mysqli("172.17.0.4", "root", "pw", "registrations");

	if ($con->connect_errno) {

		echo "connection failed: %s\n" . $con->connect_error;
		exit();
	}


	// Verify data
	$email = mysqli_escape_string($con, $_GET['email']); // Set email variable
	$codigo = mysqli_escape_string($con, $_GET['hash']); // Set hash variable

	$search = mysqli_query($con, "SELECT email, hash, active FROM users WHERE email='" . $email . "' AND hash='" . $codigo . "' AND active='0'");
	$match  = mysqli_num_rows($search);

	echo $match; // Display how many matches have been found -> remove this when done with testing ;)

	if ($match > 0) {
		// We have a match, activate the account
		mysqli_query($con, "UPDATE users SET active='1' WHERE email='" . $email . "' AND hash='" . $codigo . "' AND active='0'");
		echo '<div class="statusmsg">Your account has been activated, you can now login</div>';
	} else {
		// No match -> invalid url or account has already been activated.
		echo '<div class="statusmsg">The url is either invalid or you already have activated your account.</div>';
	}

	$res->close();
	$con->close();

	flush();
}
flush();

?>