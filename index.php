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
    if (strpos($_GET['url'], "swtest.ru") !== false) {
    
    }
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
        $msg = " <br /><h3> Your shortened URL: </h3> <p><a href=\"{$baseurl}{$check}\" target=\"_blank\">{$baseurl}{$check} </a></p>";
    } else {
        $msg = "<p class=\"error\">Invalid Url</p>";
    }
}
?>
<!DOCTYPE html>

<html lang="en">
<head>
	<title>sprk.es URL Shortener</title>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
<!--===============================================================================================-->
	<link rel="icon" type="image/png" href="images/icons/favicon.ico"/>
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="fonts/Linearicons-Free-v1.0.0/icon-font.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/css-hamburgers/hamburgers.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/animsition/css/animsition.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/daterangepicker/daterangepicker.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="css/util.css">
	<link rel="stylesheet" type="text/css" href="css/main.css">
<!--===============================================================================================-->
</head>
<body>


	<div class="container-contact100">
		<div class="wrap-contact100">
			<form class="contact100-form validate-form" action="#" method="post">
				<span class="contact100-form-title">
				SPRK.ES - URL SHORTENER
				<br />
				<br />
				<p> Sprk.es allows you to reduce long links from Facebook, YouTube, Twitter, LinkedIn and other top sites on the Internet, just paste the long URL and click the Shorten URL button. Copy the shortened URL below and share it on websites, chat and e-mail. 
		<br /><br />Please write your URL like this: https://www.dansparks.co.uk/ </p>		
				</span>

			
				<div class="wrap-input100 validate-input" data-validate="URL is required">
					<label class="label-input100" for="name">Enter your URL here:</label>
					<input id="name" class="input100" type="url" name="url" placeholder="Enter your URL here:">
					<span class="focus-input100"></span>
				</div>


			
					<div class="container-contact100-form-btn">
					<input class="contact100-form-btn" type="submit" name="submit" value="Shorten URL">
				</div>
				<center>
				
		<?php echo $msg;?>
		</center>
		
				<div class="contact100-form-social flex-c-m">
				<p> &copy <?php echo date("Y"); ?> - SPARKS (Smart programmers are required to know.)
			
					<a href="https://sprks.online">https://sprks.online/</a></p>

				</div>
			</form>

			<div class="contact100-more flex-col-c-m" style="background-image: url('images/bg-01.jpg');">
			</div>
		</div>
	</div>





<!--===============================================================================================-->
	<script src="vendor/jquery/jquery-3.2.1.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/animsition/js/animsition.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/bootstrap/js/popper.js"></script>
	<script src="vendor/bootstrap/js/bootstrap.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/select2/select2.min.js"></script>
	<script>
		$(".js-select2").each(function(){
			$(this).select2({
				minimumResultsForSearch: 20,
				dropdownParent: $(this).next('.dropDownSelect2')
			});
		})
		$(".js-select2").each(function(){
			$(this).on('select2:open', function (e){
				$(this).parent().next().addClass('eff-focus-selection');
			});
		});
		$(".js-select2").each(function(){
			$(this).on('select2:close', function (e){
				$(this).parent().next().removeClass('eff-focus-selection');
			});
		});

	</script>
<!--===============================================================================================-->
	<script src="vendor/daterangepicker/moment.min.js"></script>
	<script src="vendor/daterangepicker/daterangepicker.js"></script>
<!--===============================================================================================-->
	<script src="vendor/countdowntime/countdowntime.js"></script>
<!--===============================================================================================-->
	<script src="js/main.js"></script>
	<!-- Global site tag (gtag.js) - Google Analytics -->
	<script async src="https://www.googletagmanager.com/gtag/js?id=UA-23581568-13"></script>
	<script>
	  window.dataLayer = window.dataLayer || [];
	  function gtag(){dataLayer.push(arguments);}
	  gtag('js', new Date());

	  gtag('config', 'UA-23581568-13');
	</script>
</body>
</html>
