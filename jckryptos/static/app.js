
document.getElementById('key_id').addEventListener('change', function() {
    document.getElementById('new_key_field').style.display = (this.value === 'new') ? 'block' : 'none';
    $(document).ready(function() {
        fetchContainers();
    })
        

        $('#keyVaultButton').click(function() {
            $('#masterPasswordModal').modal('show');
        });
    
        // Handle Master Password Form Submission
        $('#masterPasswordForm').on('submit', function(event) {
            event.preventDefault();  // Prevent the default form submission
            var masterPassword = $('#masterPassword').val();
    
            $.ajax({
                url: '/verify_master_password',
                type: 'POST',
                data: {masterPassword: masterPassword},
                success: function(response) {
                    if (response.success) {
                        $('#masterPasswordModal').modal('hide');  // Hide the password modal
                        fetchAndDisplayKeys();  // Fetch and display keys if password is verified
                    } else {
                        alert(response.message || 'Incorrect master password. Please try again.');
                    }
                },
                error: function() {
                    alert('Error verifying password. Please try again later.');
                }
            });
        });
    
        // Function to fetch and display keys
        function fetchAndDisplayKeys() {
            $.ajax({
                url: '/fetch_keys',
                type: 'GET',
                success: function(response) {
                    if (response.success) {
                        var keysHTML = '';
                        response.keys.forEach(function(key) {
                            keysHTML += `<tr>
                                <td>${key.key_name}</td>
                                <td>${key.key}</td>
                            </tr>`;
                        });
                        $('#keysTableBody').html(keysHTML);
                        $('#keysModal').modal('show');
                    } else {
                        alert(response.message || 'No keys found.');
                    }
                },
                error: function() {
                    alert('Failed to fetch keys.');
                }
            });
        }

    $(document).ready(function() {
        $('#logoutButton').on('click', function() {
            $.ajax({
                url: '/logout',
                type: 'GET',
                success: function(response) {
                    window.location.href = '/';  // Redirect to the home or login page
                },
                error: function(error) {
                    console.error('Error:', error);
                    alert('Error logging out. Please try again.');
                }
            });
        });
    });
})

// Function to generate a password
function generatePassword() {
    const length = 12; // Desired password length
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let password = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
        password += charset.charAt(Math.floor(Math.random() * n));
    }
    return password;
}

// Attach click event to the generate button
document.getElementById('generateButton').addEventListener('click', function () {
    const password = generatePassword(); // Generate a new password
    const passwordField = document.getElementById('passwordField'); // Target the input field
    passwordField.value = password; // Set the generated password
});

// Copy password to clipboard
document.getElementById('copyButton').addEventListener('click', function () {
    const passwordField = document.getElementById('passwordField');
    passwordField.select(); // Select the password text
    document.execCommand('copy'); // Copy to clipboard
    alert('Password copied to clipboard!');
});

document.addEventListener('DOMContentLoaded', function () {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-title]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // No need to initialize modals; Bootstrap handles it automatically.
});

// Handle form submission for adding a container
document.getElementById('modalForm').addEventListener('submit', function (event) {
    event.preventDefault();

    var site = document.getElementById('url').value;
    var loginName = document.getElementById('email').value;
    var password = document.getElementById('password').value;
    var keyName = document.getElementById('keysName').value;
    var title = document.getElementById('title').value;

    // Print the keyName to the console
    console.log('Using key_name:', keyName);

    fetch('/add_container', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            title: title,
            email: loginName,
            password: password,
            url: site,
            key_name: keyName,
        }),
    })
        .then(response => {
            // Log the raw response for debugging
            console.log('Raw Response:', response);

            // Check for a non-2xx status
            if (!response.ok) {
                return response.json().then(data => {
                    // Show error toast with the server's error message if available
                    showToast('errorToast', data.message || 'Failed to add password. Please try again.');
                    throw new Error(data.message || 'Failed to add password');
                });
            }

            // Parse the successful JSON response
            return response.json();
        })
        .then(data => {
            console.log('Success:', data);

            // Check if the server returned an error-like response within the JSON
            if (data.error) {
                showToast('errorToast', data.error || 'An unexpected error occurred.');
                throw new Error(data.error || 'Error in response data');
            }


            // Show success toast
            showToast('successToast', 'Password added successfully!');

            // Close modal and reset form
            document.getElementById('modalForm').reset();
            var exampleModal = bootstrap.Modal.getInstance(document.getElementById('exampleModal'));
            exampleModal.hide();
        })
        .catch((error) => {
            console.error('Error:', error);

            // Show error toast for unexpected errors
            showToast('errorToast', 'An error occurred. Ensure the Key Name exists.');
        });
});


$(document).ready(function () {
    $('#myForm').on('submit', function (e) {
        e.preventDefault();

        var keyName = $('#keyName').val();
        var submitButton = $(this).find('button[type="submit"]');

        // Disable the button to prevent multiple submissions
        submitButton.prop('disabled', true).text('Generating...');

        $.ajax({
            url: '/button_action',
            type: 'POST',
            data: { key_name: keyName },
            success: function (response) {
                console.log('Success:', response);
                // Show a success toast
                showToast('successToast', 'Key generated successfully!');
                // Reset the form
                $('#myForm')[0].reset();
            },
            error: function (xhr, status, error) {
                console.error('Error:', xhr.responseText || error);
                // Show an error toast
                showToast('errorToast', xhr.responseText || 'An error occurred while generating the key.');
            },
            complete: function () {
                // Re-enable the button
                submitButton.prop('disabled', false).text('Generate Key');
            }
        });
    });
});
    // Handle logout
    $('#logoutButton').on('click', function(e) {
        e.preventDefault(); // Prevent default link behavior
        $.ajax({
            url: '/logout',
            type: 'GET',
            success: function(response) {
                window.location.href = '/';
            },
            error: function(error) {
                console.error('Error:', error);
                alert('Error logging out. Please try again.');
            }
        });
    });

// Handle master password modal
$(document).ready(function() {
    $('#masterPasswordForm').on('submit', function(event) {
        event.preventDefault();
        var masterPassword = $('#masterPassword').val();
        $.ajax({
            url: '/verify_master_password',
            type: 'POST',
            data: { masterPassword: masterPassword },
            success: function(response) {
                if (response.success) {
                    var masterPasswordModal = bootstrap.Modal.getInstance(document.getElementById('masterPasswordModal'));
                    masterPasswordModal.hide();
                    fetchAndDisplayKeys();
                } else {
                    alert(response.message || 'Incorrect master password. Please try again.');
                }
            },
            error: function() {
                alert('Error verifying password. Please try again later.');
            }
        });
    });

    function fetchAndDisplayKeys() {
        $.ajax({
            url: '/fetch_keys',
            type: 'GET',
            success: function(response) {
                if (response.success) {
                    var keysHTML = '';
                    response.keys.forEach(function(key) {
                        keysHTML += `<tr>
                            <td>${key.key_name}</td>
                            <td>${key.key}</td>
                        </tr>`;
                    });
                    $('#keysTableBody').html(keysHTML);
                    var keysModal = new bootstrap.Modal(document.getElementById('keysModal'));
                    keysModal.show();
                } else {
                    alert(response.message || 'No keys found.');
                }
            },
            error: function() {
                alert('Failed to fetch keys.');
            }
        });
    }
});
