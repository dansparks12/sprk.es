<?php
session_start(); // Make sure session is started

include 'config.php';

// Google Safe Browsing API Configuration
$googleApiKey = 'AIzaSyA9JO0JaORsvpXdPkOQMQY9YPCgKCcvEl4';
$safeBrowsingUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $googleApiKey;

// Function to generate a random short URL code
function generateShortUrl($length = 8) {
    return substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, $length);
}

// Function to normalize the URL
function normalizeUrl($url) {
    $url = trim($url);
    if (strpos($url, 'http://') === 0 || strpos($url, 'https://') === 0) {
        return $url; // Already has the scheme
    } elseif (strpos($url, 'www.') === 0) {
        return 'https://' . $url; // Add https:// if it starts with 'www.'
    } else {
        return 'https://' . $url; // Add https:// if it doesn't have any scheme
    }
}

// Function to check daily activity limits
function checkLimit($conn, $ip, $actionType, $dailyLimit) {
    $stmt = $conn->prepare("SELECT COUNT(*) AS action_count FROM url_activity WHERE ip_address = ? AND action_type = ? AND created_at >= NOW() - INTERVAL 1 DAY");
    $stmt->bind_param("ss", $ip, $actionType);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    return $result['action_count'] < $dailyLimit;
}
// Get user's IP address
$ip_address = $_SERVER['REMOTE_ADDR'];
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip_address = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
}


// Handle the redirection for shortcodes
if (isset($_GET['shortcode'])) {
    $shortcode = $_GET['shortcode'];
    $stmt = $conn->prepare('SELECT long_url FROM urls WHERE short_code = ?');
    $stmt->bind_param('s', $shortcode);
    $stmt->execute();
    $stmt->bind_result($longUrl);
    $stmt->fetch();
    if ($longUrl) {
        header("Location: $longUrl");
        exit();
    }
}

// Handle URL shortening
$shortUrl = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['long_url'])) {
	if (!checkLimit($conn, $ip_address, 'register', 5)) {
        $_SESSION['message2'] = "You've reach your daily limit.";
		header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }
    $GLOBALS['longUrl'] = $conn->real_escape_string(trim($_POST['long_url']));

    // Normalize the URL before storing or checking it
    $longUrl = normalizeUrl($longUrl);

    // Validate and check against Google Safe Browsing API
    $data = json_encode([
        'client' => ['clientId' => 'sprk', 'clientVersion' => '1.0'],
        'threatInfo' => [
            'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => [['url' => $longUrl]]
        ]
    ]);
    $response = file_get_contents($safeBrowsingUrl, false, stream_context_create([
        'http' => ['method' => 'POST', 'header' => 'Content-Type: application/json', 'content' => $data]
    ]));
    $threats = json_decode($response, true);
	$geoData = @json_decode(file_get_contents("http://ip-api.com/json/$ip_address"), true);
	
	if ($geoData && isset($geoData['status']) && $geoData['status'] === 'success') {
		$latitude = $geoData['lat'];
		$longitude = $geoData['lon'];
		$cities = $geoData['city'];
		$country = $geoData['country'];
	} else {
		// Fallback in case of error
		$latitude = $longitude = $cities = $country = 'Unavailable';
	}

    if (!empty($threats['matches'])) {
        $shortUrl = 'This URL is flagged as unsafe!';
    } else {
        // Generate a short code and insert the long URL
        $code = generateShortUrl();
        $shortUrl = "https://sprk.es/$code";
        $conn->query("SET time_zone = '+00:00'");
        $stmt = $conn->prepare('INSERT INTO urls (short_code, long_url, created_at, short_url, ip_address, latitude, longitude, city, country) VALUES (?, ?, UTC_TIMESTAMP(), ?, ?, ?, ?, ?, ?)');
        $stmt->bind_param('ssssssss', $code, $longUrl, $shortUrl, $ip_address, $latitude, $longitude, $cities, $country);
        $stmt->execute();

		$stmt = $conn->prepare('INSERT INTO url_activity (ip_address, action_type, created_at) VALUES (?, "register", NOW())');
        $stmt->bind_param('s', $ip_address);
        $stmt->execute();

        // Set session variable indicating success
        $_SESSION['shortUrl'] = $shortUrl;
		$_SESSION['longURL'] = $longUrl;

        // Redirect to prevent resubmission on refresh
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }
}

// Display the short URL after the redirect


if (isset($_SESSION['shortUrl'])) {
    $shortUrl = $_SESSION['shortUrl'];
	$longUrl = $_SESSION['longURL'];
	 // Retrieve the short URL from session
    unset($_SESSION['shortUrl']); // Clear the session after displaying it
}

// Handle malicious URL reporting
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url_to_report'])) {

	if (!checkLimit($conn, $ip_address, 'report', 2)) {
        $_SESSION['reported'] = "You've reached your daily limit.";
		header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }
    $reportedUrl = normalizeUrl($conn->real_escape_string(trim($_POST['url_to_report'])));
    $reportReason = $conn->real_escape_string(trim($_POST['report_reason']));


	// Optionally handle reverse proxy IP address forwarding
	if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$ip_address = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]; // Use first IP from the forwarded list
	}
	
	$geoData = @json_decode(file_get_contents("http://ip-api.com/json/$ip_address"), true);
	
	if ($geoData && isset($geoData['status']) && $geoData['status'] === 'success') {
		$latitude = $geoData['lat'];
		$longitude = $geoData['lon'];
		$cities = $geoData['city'];
		$country = $geoData['country'];
	} else {
		// Fallback in case of error
		$latitude = $longitude = $cities = $country = 'Unavailable';
	}

    $stmt = $conn->prepare('INSERT INTO reported_urls (url, reason, reported_at, deleted, ip_address, latitude, longitude, city, country) VALUES (?, ?, NOW(), 0, ?, ?, ?, ?, ?)');
    $stmt->bind_param('sssssss', $reportedUrl, $reportReason, $ip_address, $latitude, $longitude, $cities, $country);
    $stmt->execute();

	$stmt = $conn->prepare('INSERT INTO url_activity (ip_address, action_type, created_at) VALUES (?, "report", NOW())');
    $stmt->bind_param('s', $ip_address);
    $stmt->execute();
	$_SESSION['reported'] = "This URL has now been reported. Thank you.";
	header("Location: " . $_SERVER['PHP_SELF']);
	exit();
}

if(isset($_SESSION['reported'])) {
	$message = $_SESSION['reported'];
	unset($_SESSION['reported']);
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>sprk.es - URL shortener</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
    <link rel="stylesheet" href="assets/css/main.css" />
    <noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
</head>
<body class="is-preload landing">
<div id="page-wrapper">

    <!-- Header -->
    <header id="header">
        <h1 id="logo"><a href="index.php">sprk.es - URL Shortener</a></h1>
        <nav id="nav">
            <ul>
                <li><a href="index.php">Home</a></li>
                <li><a href="#shorten" class="button primary">Shorten</a></li>
            </ul>
        </nav>
    </header>

    <!-- Banner -->
    <section id="banner">
        <div class="content">
            <header>
                <h2>sprk.es - The next best thing...</h2>
                <p>Effortlessly shorten URLs and ensure safe web browsing.<br />
                    Powered by secure & efficient systems.</p>
            </header>
            <span class="image"><img src="images/image.png" alt="" /></span>
        </div>
        <a href="#shorten" class="goto-next scrolly">Shorten a URL</a>
    </section>

    <!-- URL Shortener Section -->
    <div id="main" class="wrapper style1">
        <div class="container">
            <section>
                <h3> URL Shortener </h3>
                <form method="post" action="#">
                    <div class="row gtr-uniform gtr-50">
                        <div class="col-10 col-12-xlarge">
                            <input type="text" name="long_url" value="" placeholder="Enter your long URL" required/>
                        </div>
                        <div class="col-12">
                            <ul class="actions">
                                <li><input type="submit" value="Shorten URL" class="primary" /></li>
                            </ul>
                        </div>
                        <div class="short-url-result">
                            <?php if (!empty($shortUrl)): ?>
                                <p>Your shortened URL is: <a href="<?php echo $shortUrl; ?>"><?php echo $shortUrl; ?></a> shortened from <a href="<?php echo $longUrl; ?>"><?php echo $longUrl; ?></a>.</p>
                            <?php endif; ?>
							<?php if (!empty($message2)): ?>
                                <p><?php echo $message2; ?></p>
                            <?php endif; ?>
                        </div>
                    </div>
                </form>
                <br />
                <h3> Report a malicious URL</h3>
                <form method="post" action="#">
                    <div class="row gtr-uniform gtr-50">
                        <div class="col-10 col-12-xlarge">
                            <input type="text" name="url_to_report" value="" placeholder="Enter the long or short URL" />
                        </div>
                        <div class="col-10 col-12-xlarge">
                            <textarea name="report_reason" placeholder="Reason for reporting this URL" rows="4" required></textarea>
                        </div>
                        <div class="col-12">
                            <ul class="actions">
                                <li><input type="submit" value="Report" class="primary" /></li>
                            </ul>
                        </div>
						<?php if (!empty($message)): ?>
                                <p><?php echo $message; ?> </p>
                            <?php endif; ?>
                    </div>
                </form>
            </section>
        </div>
    </div>
    <!-- Footer -->
    <footer id="footer">
        <ul class="copyright">
            <li>&copy; 2024 - SPRK Technologies.</li>
        </ul>
    </footer>

</div>

<!-- Scripts -->
<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/jquery.scrolly.min.js"></script>
<script src="assets/js/jquery.dropotron.min.js"></script>
<script src="assets/js/jquery.scrollex.min.js"></script>
<script src="assets/js/browser.min.js"></script>
<script src="assets/js/breakpoints.min.js"></script>
<script src="assets/js/util.js"></script>
<script src="assets/js/main.js"></script>

</body>
</html>
