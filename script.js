// ========================================
// EMAIL FORENSIC AI
// MAIN JAVASCRIPT
// ========================================


// ========================================
// FILE UPLOAD
// ========================================

const fileInput = document.getElementById("fileInput");
const browseButton = document.getElementById("browseButton");
const dropArea = document.getElementById("dropArea");

const fileBox = document.getElementById("fileBox");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");

const removeButton = document.getElementById("removeButton");
const analyzeButton = document.getElementById("analyzeButton");
const message = document.getElementById("message");

let selectedFile = null;


// Browse button

browseButton.addEventListener("click", function () {

    fileInput.click();

});


// File selected

fileInput.addEventListener("change", function () {

    if (fileInput.files.length > 0) {

        processFile(fileInput.files[0]);

    }

});


// Drag over

dropArea.addEventListener("dragover", function (event) {

    event.preventDefault();

    dropArea.classList.add("dragging");

});


// Drag leave

dropArea.addEventListener("dragleave", function () {

    dropArea.classList.remove("dragging");

});


// Drop

dropArea.addEventListener("drop", function (event) {

    event.preventDefault();

    dropArea.classList.remove("dragging");

    const file = event.dataTransfer.files[0];

    if (file) {

        processFile(file);

    }

});


// Process file

function processFile(file) {

    message.textContent = "";

    // Check extension

    if (!file.name.toLowerCase().endsWith(".eml")) {

        message.textContent =
            "Please select a valid .EML file.";

        message.style.color = "#ff5365";

        return;

    }


    // Maximum 25 MB

    const maxSize = 25 * 1024 * 1024;

    if (file.size > maxSize) {

        message.textContent =
            "File is too large. Maximum size is 25 MB.";

        message.style.color = "#ff5365";

        return;

    }


    selectedFile = file;

    fileName.textContent = file.name;

    fileSize.textContent =
        formatFileSize(file.size);

    fileBox.classList.add("show");

    message.textContent =
        "Email ready for forensic analysis.";

    message.style.color = "#35d996";

}


// File size

function formatFileSize(bytes) {

    if (bytes < 1024) {

        return bytes + " B";

    }

    if (bytes < 1024 * 1024) {

        return (bytes / 1024).toFixed(1) + " KB";

    }

    return (
        bytes / (1024 * 1024)
    ).toFixed(2) + " MB";

}


// Remove file

removeButton.addEventListener("click", function () {

    selectedFile = null;

    fileInput.value = "";

    fileBox.classList.remove("show");

    message.textContent = "";

});


// Analyze

analyzeButton.addEventListener("click", function () {

    if (!selectedFile) {

        message.textContent =
            "Please select an .EML file first.";

        message.style.color = "#ff5365";

        return;

    }


    analyzeButton.disabled = true;

    analyzeButton.innerHTML =
        "Analyzing Email <span>...</span>";

    message.textContent =
        "Running header, domain and threat analysis...";

    message.style.color = "#35d7ff";


    setTimeout(function () {

        analyzeButton.disabled = false;

        analyzeButton.innerHTML =
            "Analysis Complete <span>✓</span>";

        message.textContent =
            "Demo analysis complete. Backend integration will be added later.";

        message.style.color = "#35d996";

    }, 2500);

});


// ========================================
// PAGE NAVIGATION
// ========================================

const navItems =
    document.querySelectorAll(".nav-item");


const pages = {

    dashboard:
        document.getElementById("dashboardPage"),

    investigate:
        document.getElementById("investigatePage"),

    map:
        document.getElementById("mapPage"),

    forensics:
        document.getElementById("forensicsPage"),

    reports:
        document.getElementById("reportsPage")

};


let originMap = null;


// Navigation click

navItems.forEach(function (item) {

    item.addEventListener("click", function () {

        const pageName =
            item.getAttribute("data-page");


        // Remove active from buttons

        navItems.forEach(function (nav) {

            nav.classList.remove("active");

        });


        // Activate clicked button

        item.classList.add("active");


        // Hide all pages

        Object.values(pages).forEach(function (page) {

            page.classList.remove("active-page");

        });


        // Show selected page

        pages[pageName].classList.add("active-page");


        // If map was clicked

        if (pageName === "map") {

            setTimeout(function () {

                initializeOriginMap();

            }, 100);

        }

    });

});


// ========================================
// ORIGIN MAP
// ========================================

function initializeOriginMap() {

    // If map already exists

    if (originMap !== null) {

        originMap.invalidateSize();

        return;

    }


    // ====================================
    // TERNA ENGINEERING COLLEGE
    // ====================================

    const latitude = 19.1653;

    const longitude = 72.9972;


    // Create map

    originMap = L.map("originMap", {

        center: [
            latitude,
            longitude
        ],

        zoom: 16

    });


    // OpenStreetMap

    L.tileLayer(
        "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
        {

            maxZoom: 19,

            attribution:
                "&copy; OpenStreetMap contributors"

        }
    ).addTo(originMap);


    // Marker

    const marker = L.marker([

        latitude,
        longitude

    ]).addTo(originMap);


    // Popup

    marker.bindPopup(`

        <div style="font-size:13px">

            <strong>
                Probable Origin Infrastructure
            </strong>

            <br><br>

            Terna Engineering College

            <br>

            Navi Mumbai, Maharashtra

            <br><br>

            <strong>
                Confidence: 76%
            </strong>

        </div>

    `).openPopup();

}


// ========================================
// INVESTIGATE BUTTON
// ========================================

const investigateUpload =
    document.getElementById("investigateUpload");


investigateUpload.addEventListener(
    "click",
    function () {

        // Go back to dashboard

        navItems.forEach(function (nav) {

            nav.classList.remove("active");

        });


        navItems[0].classList.add("active");


        Object.values(pages).forEach(
            function (page) {

                page.classList.remove(
                    "active-page"
                );

            }
        );


        pages.dashboard.classList.add(
            "active-page"
        );


        // Scroll to upload section

        document.querySelector(
            ".upload-card"
        ).scrollIntoView({

            behavior: "smooth"

        });

    }
);