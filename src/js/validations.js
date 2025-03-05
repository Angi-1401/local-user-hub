// Username Regex (Allows letters, numbers and underscores; 6-16 characters)
const usernameRegex = /^[a-zA-Z0-9_-]{1,}$/;
// Email Regex (Allows email-like expressions)
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
// Password Regexs (Allows letters, numbers and special characters; 8-32 characters)
const passwordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,32}$/;

/**
 * Validate a username against a regular expression.
 *
 * @param {string} username - The username to validate.
 * @return {boolean} True if the username is valid, false otherwise.
 */
function validateUsername(username) {
  const isValid = usernameRegex.test(username);
  if (!isValid) {
    alert(
      "Username must be between 6 and 16 characters and contain only letters, numbers, and underscores."
    );
    return false;
  }
  return true;
}

/**
 * Validate an email address against a regular expression.
 *
 * @param {string} email - The email address to validate.
 * @return {boolean} True if the email address is valid, false otherwise.
 */
function validateEmail(email) {
  const isValid = emailRegex.test(email);
  if (!isValid) {
    alert("Please enter a valid email address.");
    return false;
  }
  return true;
}

/**
 * Validate a password against a regular expression.
 *
 * @param {string} password - The password to validate.
 * @return {boolean} True if the password is valid, false otherwise.
 */
function validatePassword(password) {
  const isValid = passwordRegex.test(password);
  if (!isValid) {
    alert(
      "Password must be between 8 and 32 characters and contain only letters, numbers, and special characters."
    );
    return false;
  }
  return true;
}
