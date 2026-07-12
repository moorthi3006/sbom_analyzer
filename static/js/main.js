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

// Upload form AJAX handling with progress
document.addEventListener('DOMContentLoaded', function () {
    const uploadForm = document.getElementById('uploadForm');
    if (!uploadForm) return;

    const uploadBtn = document.getElementById('uploadBtn');
    const progressWrap = document.getElementById('uploadProgress');
    const progressBar = document.getElementById('uploadProgressBar');
    const uploadStatus = document.getElementById('uploadStatus');
    const recentCard = document.getElementById('recentUploadsCard');
    const recentBody = document.getElementById('recentUploadsBody');
    const fileInput = document.getElementById('sbomFile');

    const MAX_BYTES = 10 * 1024 * 1024; // 10MB client-side limit

    uploadForm.addEventListener('submit', function (e) {
        e.preventDefault();
        if (!fileInput || !fileInput.files || !fileInput.files.length) {
            uploadStatus.innerHTML = '<span class="text-danger">No file selected.</span>';
            return;
        }

        const file = fileInput.files[0];
        const ext = file.name.split('.').pop().toLowerCase();
        if (!['json', 'csv'].includes(ext)) {
            uploadStatus.innerHTML = '<span class="text-danger">Invalid file type. Use JSON or CSV.</span>';
            return;
        }
        if (file.size > MAX_BYTES) {
            uploadStatus.innerHTML = '<span class="text-danger">File too large (max 10MB).</span>';
            return;
        }

        const formData = new FormData(uploadForm);

        uploadBtn.disabled = true;
        progressWrap.style.display = 'block';
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        uploadStatus.innerHTML = '';
        showGlobalSpinner();

        const xhr = new XMLHttpRequest();
        xhr.open('POST', uploadForm.action.replace(/\/$/, '') + '/api');

        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percent + '%';
                progressBar.textContent = percent + '%';
            }
        };

        xhr.onload = function () {
            uploadBtn.disabled = false;
            hideGlobalSpinner();
            try {
                const resp = JSON.parse(xhr.responseText);
                if (resp.success) {
                    progressBar.style.width = '100%';
                    progressBar.textContent = '100%';
                    uploadStatus.innerHTML = '<span class="text-success">' + resp.message + '</span>';
                    // show recent uploads
                    if (recentCard && recentBody) {
                        recentCard.style.display = 'block';
                        const li = document.createElement('div');
                        li.className = 'mb-2';
                        const now = new Date().toLocaleString();
                        const link = resp.redirect ? ('<a href="' + resp.redirect + '">View Application</a>') : '';
                        li.innerHTML = '<strong>' + (file.name) + '</strong><br/><small class="text-muted">' + now + ' &middot; ' + link + '</small>';
                        recentBody.insertBefore(li, recentBody.firstChild);
                    }
                    // optionally redirect after short delay
                    if (resp.redirect) {
                        setTimeout(function () { window.location = resp.redirect; }, 1800);
                    }
                } else {
                    uploadStatus.innerHTML = '<span class="text-danger">' + (resp.message || 'Upload failed') + '</span>';
                }
            } catch (err) {
                uploadStatus.innerHTML = '<span class="text-danger">Unexpected server response.</span>';
            }
            setTimeout(function () {
                progressWrap.style.display = 'none';
            }, 1200);
        };

        xhr.onerror = function () {
            uploadBtn.disabled = false;
            hideGlobalSpinner();
            uploadStatus.innerHTML = '<span class="text-danger">Network error during upload.</span>';
            progressWrap.style.display = 'none';
        };

        xhr.send(formData);
    });
});
