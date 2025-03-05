/**
 * Main logic of the application
 *
 * Index:
 * - Local Storage manipulation
 * - CRUD operations
 * - Cookies
 * - Encryption scripts
 * - Authentication/Authorization
 * - Render specific HTML Components
 */

/**
 * Local Storage manipulation
 */

/**
 * Retrieves the array of user objects from the local storage
 * and parses it into JSON format for further usage.
 *
 * @returns {Array} The array of user objects
 */
function getUsersFromLocalStorage() {
  const users = localStorage.getItem("users");
  return users ? JSON.parse(users) : [];
}

/**
 * Saves an array of user objects to local storage in JSON string format.
 *
 * @param {Array} users - The array of user objects to be stored.
 */
function saveUsersToLocalStorage(users) {
  localStorage.setItem("users", JSON.stringify(users));
}

/**
 * CRUD operations
 */

/**
 * Creates a new user and saves it to the local storage.
 * If the user with the provided username or email already exists, alert a message and return false.
 *
 * @param {string} username - The username to be created.
 * @param {string} email - The email to be created.
 * @param {string} password - The password for the new user.
 * @param {string} [role="user"] - The role for the new user. Default is "user".
 * @returns {boolean} True if the user is created, false if the user already exists.
 */

function createUser(username, email, password, role = "user") {
  const users = getUsersFromLocalStorage();

  if (users.some((u) => u.username === username || u.email === email)) {
    alert("Username or email already exists.");
    return false;
  }

  const user = { username, email, password, role };
  users.push(user);
  saveUsersToLocalStorage(users);
  return true;
}

/**
 * Updates a user and saves it to the local storage.
 * If the user with the provided email already exists, alert a message and return false.
 *
 * @param {string} username - The username to be updated.
 * @param {string} email - The email to be updated.
 * @param {string} password - The password for the updated user.
 * @param {string} [role="user"] - The role for the updated user. Default is "user".
 * @returns {boolean} True if the user is updated, false if the user with the email already exists.
 */
function updateUser(username, email, password, role = "user") {
  const users = getUsersFromLocalStorage();
  const specifiedUser = users.find((u) => u.username === username);
  const filteredUsers = users.filter(
    (u) => u.username !== specifiedUser.username
  );

  if (filteredUsers.some((u) => u.email === email)) {
    alert("Email already exists.");
    return false;
  }

  specifiedUser.email = email;
  specifiedUser.password = password;
  specifiedUser.role = role;

  saveUsersToLocalStorage(users);
  return true;
}

/**
 * Deletes a user from the local storage.
 * Returns true if the user is deleted, false otherwise.
 *
 * @param {string} username - The username of the user to be deleted.
 * @returns {boolean} True if the user is deleted, false otherwise.
 */
function deleteUser(username) {
  const users = getUsersFromLocalStorage();
  const filteredUsers = users.filter((u) => u.username !== username);
  saveUsersToLocalStorage(filteredUsers);
  return true;
}

/**
 * Cookies
 */

/**
 * Sets a cookie with the specified name and value, and an expiration time in hours.
 *
 * @param {string} name - The name of the cookie.
 * @param {string} value - The value to be stored in the cookie.
 * @param {number} hours - The number of hours until the cookie expires.
 */
function setCookie(name, value, hours) {
  const date = new Date();
  date.setTime(date.getTime() + hours * 60 * 60 * 1000);
  document.cookie = `${name}=${value}; expires=${date.toUTCString()}; path=/`;
}

/**
 * Gets the value of a cookie by name.
 *
 * @param {string} name - The name of the cookie.
 * @returns {string|null} The value of the cookie, or null if the cookie does not exist.
 */
function getCookie(name) {
  const cookies = document.cookie.split(";");
  for (let cookie of cookies) {
    let [key, value] = cookie.trim().split("=");
    if (key === name) return value;
  }
  return null;
}

/**
 * Encryption scripts
 */

/**
 * Converts a given buffer to a hexadecimal string.
 *
 * @param {Buffer} buffer - The buffer to be converted.
 * @returns {string} The hexadecimal string representation of the buffer.
 */
function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Computes the SHA-256 hash of a given input string.
 *
 * @param {string} input - The input string to be hashed.
 * @returns {Promise<string>} A promise that resolves to a hexadecimal string representation of the SHA-256 hash.
 */
async function sha256(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bufferToHex(hashBuffer);
}

/**
 * Computes a salted hash of a given raw password.
 *
 * @param {string} rawPassword - The password to be hashed.
 * @param {{salt: number|string, rounds: number}} options - Options to be passed to the hash function.
 * If not provided, defaults are used.
 * @returns {Promise<string>} A promise that resolves to a string of the form "salt$rounds$hashedPassword".
 */
async function hash(rawPassword, options = {}) {
  const salt = options.salt ? options.salt : new Date().getTime();
  const rounds = options.rounds ? options.rounds : 10;

  let hashed = await sha256(rawPassword + salt);
  for (let i = 0; i <= rounds; i++) {
    hashed = await sha256(hashed);
  }
  return `${salt}$${rounds}$${hashed}`;
}

/**
 * Compares a raw password with a hashed password to verify if they match.
 *
 * @param {string} rawPassword - The raw password to be compared.
 * @param {string} hashedPassword - The hashed password to compare against, in the format "salt$rounds$hashedPassword".
 * @returns {Promise<boolean>} A promise that resolves to true if the passwords match, false otherwise.
 * @throws {Error} Throws an error if there is an issue during the comparison process.
 */
async function compare(rawPassword, hashedPassword) {
  try {
    const [salt, rounds] = hashedPassword.split("$");
    const hashedRawPassword = await hash(rawPassword, { salt, rounds });
    return hashedPassword === hashedRawPassword;
  } catch (error) {
    throw Error(error.message);
  }
}

/**
 * Authentication/Authorization
 */

/**
 * Signs up a new user with the given username, email, and password.
 *
 * @param {string} username - The username for the new user.
 * @param {string} email - The email address for the new user.
 * @param {string} password - The plaintext password for the new user.
 * @returns {void} Redirects to ./signin.html if the signup is successful.
 */
function signup(username, email, password) {
  const success = createUser(username, email, password);
  if (success) {
    window.location.href = "./signin.html";
  }
}

/**
 * Signs in a user with the provided username and password.
 *
 * This function retrieves the list of users from local storage and verifies
 * if there is a user with the given username. If a matching user is found,
 * it compares the provided password with the stored hashed password. If the
 * passwords match, a cookie representing the active user is set, and the
 * user is redirected to the home page. If the username or password is invalid,
 * an alert is shown with an error message.
 *
 * @param {string} username - The username of the user attempting to sign in.
 * @param {string} password - The plaintext password of the user attempting to sign in.
 * @returns {void} Redirects to the home page if sign-in is successful; otherwise, shows an alert.
 */
async function signin(username, password) {
  const users = getUsersFromLocalStorage();
  const user = users.find((u) => u.username === username);
  if (user) {
    const isValid = await compare(password, user.password);
    if (isValid) {
      setCookie("activeUser", username, 2);
      window.location.href = "./home.html";
    }
  } else {
    alert("Invalid username or password.");
  }
}

/**
 * Signs out the active user by removing the activeUser cookie and
 * redirecting to the signout page.
 *
 * @returns {void} Redirects to the signout page.
 */

function signout() {
  document.cookie =
    "activeUser=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
  window.location.href = "./signout.html";
}

/**
 * Checks if a user is authenticated and redirects to the 403 page
 * if not authenticated.
 *
 * @returns {void} Redirects to 403 page if not authenticated.
 */
function isAuthenticated() {
  const activeUser = getCookie("activeUser");
  if (!activeUser) {
    window.location.href = "./403.html";
  }
}

/**
 * Checks if a user is authorized and redirects to the 403-internal page
 * if not authorized.
 *
 * @returns {void} Redirects to 403-internal page if not authorized.
 */
function isAuthorized() {
  const users = getUsersFromLocalStorage();
  const activeUser = users.find((u) => u.username === getCookie("activeUser"));
  if (!activeUser) {
    window.location.href = "./403.html";
  } else if (activeUser.role !== "admin") {
    window.location.href = "./403-internal.html";
  }
}

/**
 * Render specific HTML Components
 */

/**
 * Renders the active user's details (username and email) in the
 * active-user-details-container element.
 *
 * @returns {void} Renders the active user's details.
 */
function renderActiveUserDetails() {
  const users = getUsersFromLocalStorage();
  const activeUser = users.find((u) => u.username === getCookie("activeUser"));

  const activeUserDetailsContainer = document.getElementById(
    "active-user-details-container"
  );
  activeUserDetailsContainer.innerHTML = `
    <span class="block text-sm text-gray-900 dark:text-white">
      ${activeUser.username}
    </span>
    <span
      class="block text-sm text-gray-500 truncate dark:text-gray-400">
      ${activeUser.email}
    </span>
  `;
}
