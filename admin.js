
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    registerForm.addEventListener('submit', submitForm);
});

class admin {
    constructor() {
      // Database or storage for user information
      this.users = [];
    }
  
    static instance;
  
    static getInstance() {
      if (!admin.instance) {
        admin.instance = new admin();
      }
      return admin.instance;
    }
  
    registerUser(username, password) {
      const newUser = new User(username, password);
      this.users.push(newUser);
    }
  
    loginUser(username, password) {
      const user = this.users.find(u => u.getUsername() === username && u.getPassword() === password);
      return !!user; // Return true if user is found, indicating successful login
    }
  }
  
  
  
  // Example usage
  const admin=admin.getInstance();
  
  admin.registerUser('user1', 'password123');
  const loginResult = admin.loginUser('user1', 'password123');
  
  console.log(`Login Result: ${loginResult}`); // Should print "Login Result: true"
  
