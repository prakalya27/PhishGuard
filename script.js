function checkURL() {

    const urlInput = document.getElementById("urlInput");
    const result = document.getElementById("result");

    const url = urlInput.value.trim();

    if (url === "") {
        result.innerHTML = `
            <div class="result-icon">⚠️</div>
            <h3>Please enter a URL</h3>
            <p>Enter a website address before starting the security scan.</p>
        `;
        return;
    }

    let riskScore = 0;
    let warnings = [];
    let checks = [];

    const lowerURL = url.toLowerCase();

    // HTTPS check
    if (lowerURL.startsWith("https://")) {

        checks.push("✅ HTTPS encryption detected");

    } else {

        riskScore += 20;
        checks.push("⚠️ HTTPS encryption not detected");
        warnings.push("The website does not use HTTPS.");
    }

    // Suspicious keywords
    const suspiciousWords = [
        "login",
        "verify",
        "password",
        "bank",
        "secure",
        "account",
        "claim",
        "winner",
        "free",
        "urgent",
        "update",
        "confirm"
    ];

    let detectedKeywords = [];

    suspiciousWords.forEach(function(word) {

        if (lowerURL.includes(word)) {
            detectedKeywords.push(word);
        }

    });

    if (detectedKeywords.length > 0) {

        riskScore += detectedKeywords.length * 10;

        checks.push(
            "⚠️ Suspicious keywords detected"
        );

        warnings.push(
            "Suspicious keywords: " +
            detectedKeywords.join(", ")
        );

    } else {

        checks.push("✅ No suspicious keywords detected");

    }

    // IP address detection
    const ipPattern =
        /https?:\/\/\d{1,3}(\.\d{1,3}){3}/;

    if (ipPattern.test(url)) {

        riskScore += 25;

        checks.push("⚠️ IP address used instead of domain");

        warnings.push(
            "The URL uses an IP address instead of a normal domain name."
        );

    } else {

        checks.push("✅ Normal domain structure detected");

    }

    // @ symbol detection
    if (url.includes("@")) {

        riskScore += 20;

        checks.push("⚠️ Unusual @ symbol detected");

        warnings.push(
            "The URL contains an unusual @ symbol."
        );

    } else {

        checks.push("✅ No unusual @ symbol detected");

    }

    // URL length
    if (url.length > 100) {

        riskScore += 10;

        checks.push("⚠️ Unusually long URL");

        warnings.push(
            "The URL is unusually long."
        );

    } else {

        checks.push("✅ URL length looks normal");

    }

    // URL shortening services
    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "shorturl.at",
        "goo.gl"
    ];

    let shortened = shorteners.some(function(service) {
        return lowerURL.includes(service);
    });

    if (shortened) {

        riskScore += 15;

        checks.push("⚠️ URL shortener detected");

        warnings.push(
            "A URL shortening service was detected."
        );

    } else {

        checks.push("✅ No common URL shortener detected");

    }

    // Limit score
    if (riskScore > 100) {
        riskScore = 100;
    }

    // Risk level
    let status;
    let statusIcon;

    if (riskScore >= 60) {

        status = "High Risk";
        statusIcon = "🔴";

    } else if (riskScore >= 30) {

        status = "Suspicious";
        statusIcon = "🟠";

    } else {

        status = "Low Risk";
        statusIcon = "🟢";
    }

    // Warning section
    let warningHTML = "";

    if (warnings.length > 0) {

        warningHTML = `
            <div class="analysis-section">
                <h4>⚠️ Detected Indicators</h4>

                <ul>
                    ${warnings.map(function(item) {
                        return `<li>${item}</li>`;
                    }).join("")}
                </ul>
            </div>
        `;

    } else {

        warningHTML = `
            <div class="analysis-section">
                <h4>✅ No Obvious Warnings</h4>

                <p>
                    No obvious suspicious patterns were detected
                    by this demo analysis.
                </p>
            </div>
        `;
    }

    // Security checks
    const checksHTML = `
        <div class="analysis-section">

            <h4>Security Checks</h4>

            <ul>
                ${checks.map(function(item) {
                    return `<li>${item}</li>`;
                }).join("")}
            </ul>

        </div>
    `;

    // Final result
    result.innerHTML = `

        <div class="result-icon">
            ${statusIcon}
        </div>

        <h3>${status}</h3>

        <div class="risk-score">
            Risk Score: <strong>${riskScore}%</strong>
        </div>

        ${warningHTML}

        ${checksHTML}

        <div class="community-note">

            👥 Community Reports

            <p>
                Demo mode — not connected to a
                real spam-report database.
            </p>

        </div>

        <p class="security-disclaimer">

            ⚠️ This is a risk assessment, not a guarantee
            that the website is safe or malicious.

        </p>
    `;
}


// QR upload handler
// QR image scanner
async function scanQR() {

    const fileInput = document.getElementById("qrFile");
    const qrResult = document.getElementById("qrResult");

    if (!fileInput || fileInput.files.length === 0) {
        return;
    }

    const file = fileInput.files[0];

    qrResult.innerHTML = "🔍 Reading QR code...";

    const scanner = new Html5Qrcode("qr-reader");

    try {

        const decodedText = await scanner.scanFile(file, true);

        qrResult.innerHTML = `
            ✅ QR code detected!
            <br><br>
            <strong>URL:</strong> ${decodedText}
        `;

        document.getElementById("urlInput").value = decodedText;

        checkURL();

    } catch (error) {

        qrResult.innerHTML = `
            ❌ Could not detect a QR code.
            <br><br>
            Please upload a clear QR-code image.
        `;

    } finally {

        try {
            await scanner.clear();
        } catch (error) {
            console.log(error);
        }

    }
}
function startQRScanner() {

    const qrResult = document.getElementById("qrResult");

    qrResult.innerHTML = "📷 Starting camera...";

    const scanner = new Html5Qrcode("qr-reader");

    scanner.start(
        { facingMode: "environment" },
        {
            fps: 10,
            qrbox: 250
        },

        function(decodedText) {

            document.getElementById("urlInput").value = decodedText;

            qrResult.innerHTML =
                "✅ QR code detected. URL added to scanner.";

            scanner.stop().then(function() {

                checkURL();

            });

        },

        function(errorMessage) {
            // Scanner is continuously looking for a QR code.
        }

    ).catch(function(error) {

        qrResult.innerHTML =
            "⚠️ Camera could not be started. Please allow camera permission.";

        console.log(error);

    });
}