<?php
session_start();

include 'config.php';

// Check if the user is logged in
if (!isset($_SESSION['admin_logged_in'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
        $inputUsername = $_POST['username'];
        $inputPassword = $_POST['password'];

        $stmt = $conn->prepare("SELECT password_hash FROM admin_users WHERE username = ?");
        $stmt->bind_param("s", $inputUsername);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($passwordHash);
            $stmt->fetch();
            if (password_verify($inputPassword, $passwordHash)) {
                $_SESSION['admin_logged_in'] = true;
                header('Location: admin.php');
                exit;
            } else {
                $errorMessage = 'Invalid username or password.';
            }
        } else {
            $errorMessage = 'Invalid username or password.';
        }
        $stmt->close();
    }

    echo '<!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
        <link rel="stylesheet" href="assets/css/main.css" />
    </head>
    <body>
        <section id="login">
        <div class="container">
            <h2>Admin Login</h2>
            <form method="POST">
                <div class="row gtr-uniform gtr-50">
                    <div class="col-12">
                        <input type="text" name="username" placeholder="Username" required />
                    </div>
                    <div class="col-12">
                        <input type="password" name="password" placeholder="Password" required />
                    </div>
                    <div class="col-12">
                        <ul class="actions">
                            <li><input type="submit" name="login" value="Login" class="primary" /></li>
                        </ul>
                    </div>
                </div>
                </div>
            </form>';
    if (isset($errorMessage)) echo '<p style="color:red;">' . htmlspecialchars($errorMessage) . '</p>';
    echo '</body></html>';
    exit;
}

// Handle deletion of reported URLs
if (isset($_POST['delete_url'])) {
    $urlToDelete = $conn->real_escape_string($_POST['delete_url']);
    $conn->query("DELETE FROM urls WHERE long_url = '$urlToDelete' OR short_url = '$urlToDelete'");
    $conn->query("UPDATE reported_urls SET deleted = 1 WHERE url = '$urlToDelete'");
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}
if (isset($_POST['short_delete'])) {
    $urlToDelete = $conn->real_escape_string($_POST['short_delete']);
    $conn->query("DELETE FROM urls WHERE short_code = '$urlToDelete'");
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Handle ignoring a reported URL
if (isset($_POST['ignore_report'])) {
    $id = $conn->real_escape_string($_POST['ignore_report']);
    $conn->query("DELETE FROM reported_urls WHERE id = $id");
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

// Stats queries
$totalUrlsQuery = $conn->query("SELECT COUNT(*) AS total_urls FROM urls");
$totalUrls = $totalUrlsQuery->fetch_assoc()['total_urls'];

$totalReportedUrlsQuery = $conn->query("SELECT COUNT(*) AS total_reported_urls FROM reported_urls");
$totalReportedUrls = $totalReportedUrlsQuery->fetch_assoc()['total_reported_urls'];

$deletedurlsQuery = $conn->query("SELECT COUNT(*) AS deleted_urls FROM reported_urls WHERE deleted = 1");
$totalDeleted = $deletedurlsQuery->fetch_assoc()['deleted_urls'];

$reportReasonsQuery = $conn->query("SELECT reason, COUNT(*) AS count FROM reported_urls GROUP BY reason");
$reportReasons = [];
while ($row = $reportReasonsQuery->fetch_assoc()) {
    $reportReasons[] = $row;
}

// Fetch locations for registered URLs
$registeredLocationsQuery = $conn->query("SELECT short_code, long_url, ip_address, city, country, latitude AS lat, longitude AS lon FROM urls WHERE latitude IS NOT NULL AND longitude IS NOT NULL");
$registeredLocations = [];
while ($row = $registeredLocationsQuery->fetch_assoc()) {
    $registeredLocations[] = $row;
}
$registeredLocationsJson = json_encode($registeredLocations);

// Fetch locations for reported URLs
$reportedLocationsQuery = $conn->query("SELECT url, reason, ip_address, city, country, latitude AS lat, longitude AS lon FROM reported_urls WHERE latitude IS NOT NULL AND longitude IS NOT NULL");
$reportedLocations = [];
while ($row = $reportedLocationsQuery->fetch_assoc()) {
    $reportedLocations[] = $row;
}
$reportedLocationsJson = json_encode($reportedLocations);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="assets/css/main.css" />
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div id="page-wrapper">

        <!-- Header -->
        <header id="header">
            <h1 id="logo"><a href="admin.php">Admin Dashboard</a></h1>
            <nav id="nav">
                <ul>
                    <li><a href="index.php">Home</a></li>
                    <li><a href="logout.php" class="button primary">Logout</a></li>
                </ul>
            </nav>
        </header>

        <!-- Main Section -->
        <section id="main">
            <div class="container">
                <br />
                <header>
                    <h2>Admin Dashboard</h2>
                </header>

             
                <br />    
                <h3>Statistics</h3>
                <!-- Charts section -->
                <div class="row">
                    <div class="col-6 col-12-medium">
                        <canvas id="urlChart"></canvas>
                    </div>
                    <div class="col-6 col-12-medium">
                        <canvas id="reasonChart"></canvas>
                    </div>
                </div>

                <!-- All Shortened URLs -->
                <h3>All Shortened URLs</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Short URL</th>
                            <th>Long URL</th>
                            <th>Created At</th>
                            <th> Location </th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $result = $conn->query("SELECT * FROM urls");
                        while ($row = $result->fetch_assoc()):
                        ?>
                            <tr>
                                <td><a href="http://sprk.es/<?= htmlspecialchars($row['short_code']) ?>" target="_blank">http://sprk.es/<?= htmlspecialchars($row['short_code']) ?></a></td>
                                <td><?= htmlspecialchars($row['long_url']) ?></td>
                                <td><?= htmlspecialchars($row['created_at']) ?></td>
                                <td><?= htmlspecialchars($row['city'] . " - " . htmlspecialchars($row['country'])) ?></td>
                                <td>
                                    <form method="POST" style="display:inline;">
                                        <button name="short_delete" value="<?= htmlspecialchars($row['short_code']) ?>">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>

                <!-- Reported URLs -->
                <h3>Reported URLs</h3>
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Reason</th>
                            <th>Reported At</th>
                            <th> Location </th>
                            <th> Status </th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $reportedResult = $conn->query("SELECT * FROM reported_urls");
                        while ($row = $reportedResult->fetch_assoc()):
                        ?>
                            <tr>
                                <td><?= htmlspecialchars($row['url']) ?></td>
                                <td><?= htmlspecialchars($row['reason']) ?></td>
                                <td><?= htmlspecialchars($row['reported_at']) ?></td>
                                <td><?= htmlspecialchars($row['city'] . " - " . htmlspecialchars($row['country'])) ?></td>
                                <?php
                                    if (htmlspecialchars($row['deleted']) == 1 ) {
                                        echo "<td> Deleted </td>";
                                    }
                                    else {
                                        echo "<td> To be reviewed </td>";
                                    }
                                ?>
                                <td>
                                    <form method="POST" style="display:inline;">
                                    <?php if (htmlspecialchars($row['deleted']) == 1 ) {
                                        echo "<button name=\"ignore_report\" value=" . htmlspecialchars($row['id']) . ">Remove from table</button>";
                                    }
                                     else {   
                                        echo "<button name=\"ignore_report\" value=" . htmlspecialchars($row['id']) . ">Ignore</button> &nbsp;";
                                        echo "<button name=\"delete_url\" value=" . htmlspecialchars($row['url']) . ">Delete</button>";
                                        }
                                        ?>
                                    </form>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
                <h3>URLs Locations Map</h3>
                <div id="map" style="height: 500px; z-index: 1;"></div>
                <br />
                <br />

            </div>
        </section>

        <!-- Footer -->
        <footer id="footer">
            <ul class="copyright">
                <li>&copy; 2024 - SPRK Technologies.</li>
            </ul>
        </footer>

    </div>

    <script>
        const map = L.map('map').setView([0, 0], 2);

        // Add OpenStreetMap tiles
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        const registeredLocations = <?= $registeredLocationsJson ?>;
        const reportedLocations = <?= $reportedLocationsJson ?>;

        // Add markers for registered locations
        registeredLocations.forEach(location => {
            if (location.lat && location.lon) {
                L.marker([location.lat, location.lon], { icon: L.icon({
                    iconUrl: 'https://maps.google.com/mapfiles/ms/icons/green-dot.png',
                    iconSize: [32, 32]
                })}).addTo(map)
                    .bindPopup(`
                        ${location.ip_address}<br>
                        http://sprk.es/${location.short_code}<br>
                        ${location.long_url}<br>
                        ${location.city}, ${location.country}
                    `);
            }
        });

        // Add markers for reported locations
        reportedLocations.forEach(location => {
            if (location.lat && location.lon) {
                L.marker([location.lat, location.lon], { icon: L.icon({
                    iconUrl: 'https://maps.google.com/mapfiles/ms/icons/red-dot.png',
                    iconSize: [32, 32]
                })}).addTo(map)
                    .bindPopup(`
                        Reported URL<br>
                        ${location.ip_address}<br>
                         ${location.url}<br>
                         ${location.reason}<br>
                        ${location.city}, ${location.country}
                    `);
            }
        });
    </script>

    <!-- Chart Scripts -->
    <script>
        // Data for URL stats
        const urlChartCtx = document.getElementById('urlChart').getContext('2d');
        new Chart(urlChartCtx, {
            type: 'bar',
            data: {
                labels: ['Shortened URLs', 'Reported URLs' , 'Deleted URLs'],
                datasets: [{
                    label: 'Count',
                    data: [<?= $totalUrls ?>, <?= $totalReportedUrls ?>, <?= $totalDeleted ?>],
                    backgroundColor: ['#4caf50', '#f44336', '#428af5'],
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                    title: { display: true, text: 'URLs Summary' }
                }
            }
        });
// Function to generate random colors
function generateRandomColor() {
    const letters = '0123456789ABCDEF';
    let color = '#';
    for (let i = 0; i < 6; i++) {
        color += letters[Math.floor(Math.random() * 16)];
    }
    return color;
}

// Data for reasons pie chart
const reasonChartCtx = document.getElementById('reasonChart').getContext('2d');

// Get the number of report reasons
const reportReasons = <?= json_encode($reportReasons) ?>;
const labels = <?= json_encode(array_column($reportReasons, 'reason')) ?>;
const data = <?= json_encode(array_column($reportReasons, 'count')) ?>;

// Generate a background color array based on the number of entries
const backgroundColors = reportReasons.map(() => generateRandomColor());

const reasonData = {
    labels: labels,
    datasets: [{
        label: 'Reports by Reason',
        data: data,
        backgroundColor: backgroundColors,
    }]
};

new Chart(reasonChartCtx, {
    type: 'pie',
    data: reasonData,
    options: {
        responsive: true,
        plugins: {
            title: { display: true, text: 'Reported URLs by Reason' }
        }
    }
});

    </script>
</body>
</html>