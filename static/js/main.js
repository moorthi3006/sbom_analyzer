document.addEventListener('DOMContentLoaded', function () {
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('sbomFile');

    if (uploadZone && fileInput) {
        uploadZone.addEventListener('dragover', function (e) {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });

        uploadZone.addEventListener('dragleave', function () {
            uploadZone.classList.remove('dragover');
        });

        uploadZone.addEventListener('drop', function (e) {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
            }
        });
    }

    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 5000);
    });
});

function showGlobalSpinner() {
    const s = document.getElementById('globalSpinner');
    if (s) s.classList.remove('d-none');
}

function hideGlobalSpinner() {
    const s = document.getElementById('globalSpinner');
    if (s) s.classList.add('d-none');
}

// Optional: show spinner on any form submit to give user feedback
document.addEventListener('submit', function (e) {
    const form = e.target;
    if (form && form.tagName === 'FORM' && !form.classList.contains('no-spinner')) {
        showGlobalSpinner();
    }
});
