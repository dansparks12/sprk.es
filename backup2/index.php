<?php
$baseurl = 'https://sprk.es/';
$msg = '';

function short_url($url)
{
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        $rand_str = substr(rand(),0,9);
        $oldfile = file_get_contents('url_list.php')."\n";
        $newfile = '$list[\''.$rand_str.'\']=\''.$url.'\';';
        file_put_contents('url_list.php', $oldfile.$newfile);
        return $rand_str;
    } else {
        return false;
    }
}

if (isset($_GET['url'])) {
    require_once('url_list.php');
    if (isset($list[$_GET['url']])) {
        $link = $list[$_GET['url']];
        header('location:'.$link);
    } else {
        header('location:'.$baseurl);
    }
} elseif (isset($_POST['url'])) {
    $check = short_url($_POST['url']);
    if ($check) {
        $msg = "<p class=\"success\">Url Created
        <a href=\"{$baseurl}{$check}\" target=\"_blank\">{$baseurl}{$check} </a></p>";
    } else {
        $msg = "<p class=\"error\">Invalid Url</p>";
    }
}
?>
<!DOCTYPE HTML>
<html>
	<head>
		<title>sprk.es URL Shortener</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		
		<link rel="stylesheet" href="assets/css/main.css" />
		<noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
	</head>
	<body class="is-preload">

		<!-- Wrapper -->
			<div id="wrapper">

				<!-- Main -->
					<section id="main">
						<header>
							<h1>sprk.es URL Shortener</h1>
							<p>Shorten your URL's here!</p>
							<p> Please write your URL like this: <br /> https://www.dansparks.co.uk/ </p>
							<br />
							<br />
							<?php echo $msg;?>
   						 <form action="#" method="post">
      				  <input type="url" style="width:100%;" name="url" placeholder="Enter URL">
       					 <br />
						<br />
        			<input type="submit" name="submit" value="Shorten">
    				</form>
						</header>
					</section>

				<!-- Footer -->
					<footer id="footer">
						<ul class="copyright">
							<li>&copy; <?php echo date("Y");  ?> Dan Sparks. <a href="https://dansparks.co.uk" target="_blank"> https://www.dansparks.co.uk</a></li><li>
						</ul>
					</footer>

			</div>

		<!-- Scripts -->
			<script>
				if ('addEventListener' in window) {
					window.addEventListener('load', function() { document.body.className = document.body.className.replace(/\bis-preload\b/, ''); });
					document.body.className += (navigator.userAgent.match(/(MSIE|rv:11\.0)/) ? ' is-ie' : '');
				}
			</script>

	</body>
</html>