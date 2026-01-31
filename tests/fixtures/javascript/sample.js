// Sample JavaScript file for testing

// Function call examples
const result = fetch('/api/users');
document.getElementById('container');
console.log('Hello, world!');

// Template literal examples
const userId = 123;
const query = `SELECT * FROM users WHERE id = ${userId}`;
const greeting = `Hello, ${name}!`;

// Assignment examples
const apiKey = "secret-key-12345";
let password = process.env.PASSWORD;

// Function definitions
function greet(name) {
    return `Hello, ${name}!`;
}

const arrowFunc = (x) => x * 2;

async function fetchData(url) {
    const response = await fetch(url);
    return response.json();
}

// Class definition
class UserService {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
    }

    async getUser(id) {
        return fetch(`${this.apiUrl}/users/${id}`);
    }
}

// Object with method
const utils = {
    formatName: function(first, last) {
        return `${first} ${last}`;
    }
};

// Nested function call
const data = JSON.parse(localStorage.getItem('data'));

// Chained calls
document.querySelector('.btn').addEventListener('click', handler);

export { greet, UserService };
