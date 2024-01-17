document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    registerForm.addEventListener('submit', submitForm);
});

function submitForm(event) {
    event.preventDefault();

    // Get values from the form
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Perform basic validation
    if (!username || !password) {
        document.getElementById('outputSection').innerText = 'Please fill in all fields.';
        return;
    }

    // Log the form data
    console.log('Username:', username);
    console.log('Password:', password);

    // Send the form data to the server 
    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: username,
            password: password,
        }),
    })
    .then(response => response.json())
    .then(data => {
        // Display a congratulatory message on successful registration
        window.alert('Congratulations! You have successfully registered.');
        // Redirect to the explore page or any other desired page
        window.location.href = '/explore';
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('outputSection').innerText = 'An error occurred during registration.';
    });
}
