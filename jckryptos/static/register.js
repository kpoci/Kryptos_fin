$(document).ready(function () {
    // Single Show/Hide Password Toggle
    $('#show-password-toggle').on('change', function () {
        let type = $(this).is(':checked') ? 'text' : 'password';
        $('#master_pass, #confirm_master_pass').attr('type', type); // Toggle both fields
    });

    // Suggest Password for Master Password
    $('#suggest-master-pass').on('click', function () {
        let password = generatePassword();
        $('#master_pass').val(password).trigger('input');
        $('#confirm_master_pass').val(password);
    });

    // Password Strength Meter
    $('#master_pass').on('input', function () {
        let val = $(this).val();
        let strength = getPasswordStrength(val);

        // Update the strength bar
        updateMeter(strength.score);

        // Update the text indicator
        let strengthLevels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"];
        let cappedScore = Math.min(strength.score, strengthLevels.length - 1); // Cap the score for levels
        $('#master-pass-strength-text').text("Strength: " + strengthLevels[cappedScore]);
    });

    function getPasswordStrength(password) {
        let score = 0;
        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^\w\s]/.test(password)) score++; // Special characters
        if (password.length >= 12) score++; // Extra score for length
        return { score: score };
    }

    function updateMeter(score) {
        const colors = ['red', 'orange', 'yellow', 'green', 'darkgreen'];
        const widths = ['20%', '40%', '60%', '80%', '100%'];

        score = Math.min(score, colors.length - 1);

        $('#master-pass-strength-meter').css({
            'background-color': colors[score],
            'width': widths[score]
        });
    }

    function generatePassword() {
        const length = 12;
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
        let password = "";
        for (let i = 0; i < length; ++i) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return password;
    }
});
