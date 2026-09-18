document.addEventListener("DOMContentLoaded", () => {
    // -------------------------------------------------------------
    // 1. Home Page: URL Scanning, Form Validation & Loader Animation
    // -------------------------------------------------------------
    const scanForm = document.getElementById("scan-form");
    const scanInput = document.getElementById("url-input");
    const scanBtn = document.getElementById("scan-btn");
    const scanLoader = document.getElementById("scan-loader");
    const flashMessages = document.querySelector(".alert-container");

    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            const urlVal = scanInput.value.trim();

            // Clear any existing flash messages
            if (flashMessages) {
                flashMessages.innerHTML = '';
            }

            // Client-side URL Validation
            if (!urlVal) {
                e.preventDefault();
                showClientError("URL cannot be empty.");
                return;
            }

            // Simple URL regex to verify it has HTTP/HTTPS scheme
            const urlPattern = /^(https?:\/\/)/i;
            if (!urlPattern.test(urlVal)) {
                e.preventDefault();
                showClientError("URL must be valid and start with http:// or https://");
                return;
            }

            // Show beautiful cybersecurity radar scanning loader
            scanBtn.style.display = "none";
            scanLoader.style.display = "flex";
            
            // Periodically change loader messages for immersive aesthetic
            const loaderText = scanLoader.querySelector(".loader-text");
            const loadingPhrases = [
                "INITIALIZING PACKET ANALYZER...",
                "VERIFYING SSL/HTTPS CERTIFICATE...",
                "PARSING DOMAIN TLD AND PATH...",
                "COMPUTING RISK SCORE THRESHOLDS...",
                "CONSULTING GROQ AI MODEL..."
            ];
            
            let phraseIndex = 0;
            const phraseInterval = setInterval(() => {
                if (phraseIndex < loadingPhrases.length - 1) {
                    phraseIndex++;
                    loaderText.textContent = loadingPhrases[phraseIndex];
                } else {
                    clearInterval(phraseInterval);
                }
            }, 1200);
        });
    }

    function showClientError(message) {
        let alertBox = document.createElement("div");
        alertBox.className = "alert alert-error animate__animated animate__fadeIn";
        alertBox.innerHTML = `<i class="fas fa-exclamation-triangle"></i> <span>${escapeHtml(message)}</span>`;
        
        let container = document.querySelector(".alert-container");
        if (!container) {
            container = document.createElement("div");
            container.className = "alert-container";
            const mainContent = document.querySelector(".container");
            mainContent.insertBefore(container, mainContent.firstChild);
        }
        container.appendChild(alertBox);
        
        // Auto scroll to error
        alertBox.scrollIntoView({ behavior: 'smooth' });
    }

    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // -------------------------------------------------------------
    // 2. Results Page: Gauge Count-up Micro-animation
    // -------------------------------------------------------------
    const scoreCircle = document.querySelector(".score-circle");
    if (scoreCircle) {
        const targetScore = parseInt(scoreCircle.getAttribute("data-score"), 10) || 0;
        const scoreValElement = scoreCircle.querySelector(".score-number");
        
        let currentScore = 0;
        const duration = 1200; // 1.2 seconds total animation time
        const frameRate = 60;
        const totalFrames = (duration / 1000) * frameRate;
        const increment = targetScore / totalFrames;
        
        function animateGauge() {
            if (currentScore < targetScore) {
                currentScore += increment;
                if (currentScore > targetScore) currentScore = targetScore;
                
                const roundedScore = Math.floor(currentScore);
                scoreValElement.textContent = roundedScore;
                scoreCircle.style.setProperty("--score-percent", roundedScore);
                
                requestAnimationFrame(animateGauge);
            }
        }
        
        // Start counting up
        setTimeout(animateGauge, 300);
    }

    // -------------------------------------------------------------
    // 3. Scan History Page: Real-time Client-side Filter
    // -------------------------------------------------------------
    const searchInput = document.getElementById("history-search");
    const historyTable = document.querySelector(".history-table");
    
    if (searchInput && historyTable) {
        const tableRows = historyTable.querySelectorAll("tbody tr");
        
        searchInput.addEventListener("input", (e) => {
            const query = e.target.value.toLowerCase().trim();
            let visibleRowsCount = 0;
            
            tableRows.forEach(row => {
                const urlCell = row.querySelector(".td-url");
                const riskCell = row.querySelector(".badge-risk-sm");
                
                if (urlCell && riskCell) {
                    const urlText = urlCell.textContent.toLowerCase();
                    const riskText = riskCell.textContent.toLowerCase();
                    
                    if (urlText.includes(query) || riskText.includes(query)) {
                        row.style.display = "";
                        visibleRowsCount++;
                    } else {
                        row.style.display = "none";
                    }
                }
            });
            
            // Show a "no results" message row if all rows are hidden
            let noResultRow = document.getElementById("no-results-tr");
            if (visibleRowsCount === 0) {
                if (!noResultRow) {
                    noResultRow = document.createElement("tr");
                    noResultRow.id = "no-results-tr";
                    noResultRow.innerHTML = `<td colspan="5" class="no-history"><i class="fas fa-search"></i> No matching scans found.</td>`;
                    historyTable.querySelector("tbody").appendChild(noResultRow);
                }
            } else {
                if (noResultRow) {
                    noResultRow.remove();
                }
            }
        });
    }
});
